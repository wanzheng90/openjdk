/*
 * Copyright (c) 2008, 2022, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

#include "jni.h"
#include "jni_util.h"
#include "jvm.h"
#include "jlong.h"

#include "nio.h"

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include <mntent.h>
#include <fcntl.h>
#include <asm/unistd.h> // __NR_statx
#include <sys/sysmacros.h> // makedev macros

#include <sys/sendfile.h>

#include "sun_nio_fs_LinuxNativeDispatcher.h"

// Account for the case where we compile on a system without statx
// support. We still want to ensure we can call statx at runtime
// if the runtime glibc version supports it (>= 2.28)
#ifndef __NR_statx

/*
 * Timestamp structure for the timestamps in struct statx.
 */
struct statx_timestamp {
        int64_t   tv_sec;
        __uint32_t  tv_nsec;
        int32_t   __reserved;
};

/*
 * struct statx used by statx system call on >= glibc 2.28
 * systems
 */
struct statx
{
  __uint32_t stx_mask;
  __uint32_t stx_blksize;
  __uint64_t stx_attributes;
  __uint32_t stx_nlink;
  __uint32_t stx_uid;
  __uint32_t stx_gid;
  __uint16_t stx_mode;
  __uint16_t __statx_pad1[1];
  __uint64_t stx_ino;
  __uint64_t stx_size;
  __uint64_t stx_blocks;
  __uint64_t stx_attributes_mask;
  struct statx_timestamp stx_atime;
  struct statx_timestamp stx_btime;
  struct statx_timestamp stx_ctime;
  struct statx_timestamp stx_mtime;
  __uint32_t stx_rdev_major;
  __uint32_t stx_rdev_minor;
  __uint32_t stx_dev_major;
  __uint32_t stx_dev_minor;
  __uint64_t __statx_pad2[14];
};
#else

#include <linux/stat.h> // statx and related struct defns

#endif // __NR_statx

// statx masks, flags, constants

#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW 0x100
#endif

#ifndef AT_STATX_SYNC_AS_STAT
#define AT_STATX_SYNC_AS_STAT 0x0000
#endif

#ifndef STATX_BASIC_STATS
#define STATX_BASIC_STATS    0x000007ffU
#endif

#ifndef STATX_BTIME
#define STATX_BTIME 0x00000800U
#endif

#ifndef STATX_ALL
#define STATX_ALL (STATX_BTIME | STATX_BASIC_STATS)
#endif

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

#ifndef RTLD_DEFAULT
#define RTLD_DEFAULT RTLD_LOCAL
#endif

#define NO_FOLLOW_SYMLINK 1
#define FOLLOW_SYMLINK 0

static jfieldID entry_name;
static jfieldID entry_dir;
static jfieldID entry_fstype;
static jfieldID entry_options;
static jfieldID attrs_stx_btime_nsec;
static jfieldID dp_statx_supported;

// Fields in UnixFileAttributes
static jfieldID attrs_st_mode;
static jfieldID attrs_st_ino;
static jfieldID attrs_st_dev;
static jfieldID attrs_st_rdev;
static jfieldID attrs_st_nlink;
static jfieldID attrs_st_uid;
static jfieldID attrs_st_gid;
static jfieldID attrs_st_size;
static jfieldID attrs_st_atime_sec;
static jfieldID attrs_st_atime_nsec;
static jfieldID attrs_st_mtime_sec;
static jfieldID attrs_st_mtime_nsec;
static jfieldID attrs_st_ctime_sec;
static jfieldID attrs_st_ctime_nsec;
static jfieldID attrs_st_birthtime_sec;

typedef int statx_func(int dirfd, const char *restrict pathname, int flags,
                 unsigned int mask, struct statx *restrict statxbuf);
static statx_func* my_statx_func = NULL;
static int statx_wrapper(int dirfd, const char *restrict pathname, int flags,
                 unsigned int mask, struct statx *restrict statxbuf, int follow_symlink) {
    if (follow_symlink == NO_FOLLOW_SYMLINK) {
      flags |= AT_SYMLINK_NOFOLLOW;
    }
    return (*my_statx_func)(dirfd, pathname, flags, mask, statxbuf);
}

typedef ssize_t copy_file_range_func(int, loff_t*, int, loff_t*, size_t,
                                     unsigned int);
static copy_file_range_func* my_copy_file_range_func = NULL;

#define RESTARTABLE(_cmd, _result) do { \
  do { \
    _result = _cmd; \
  } while((_result == -1) && (errno == EINTR)); \
} while(0)

static void throwUnixException(JNIEnv* env, int errnum) {
    jobject x = JNU_NewObjectByName(env, "sun/nio/fs/UnixException",
        "(I)V", errnum);
    if (x != NULL) {
        (*env)->Throw(env, x);
    }
}

JNIEXPORT void JNICALL
Java_sun_nio_fs_LinuxNativeDispatcher_init(JNIEnv *env, jclass clazz)
{
    jclass attr_class;
    jclass u_attr_class;
    jclass dispatch_class;
    clazz = (*env)->FindClass(env, "sun/nio/fs/UnixMountEntry");
    CHECK_NULL(clazz);
    entry_name = (*env)->GetFieldID(env, clazz, "name", "[B");
    CHECK_NULL(entry_name);
    entry_dir = (*env)->GetFieldID(env, clazz, "dir", "[B");
    CHECK_NULL(entry_dir);
    entry_fstype = (*env)->GetFieldID(env, clazz, "fstype", "[B");
    CHECK_NULL(entry_fstype);
    entry_options = (*env)->GetFieldID(env, clazz, "opts", "[B");
    CHECK_NULL(entry_options);

    dispatch_class = (*env)->FindClass(env, "sun/nio/fs/LinuxNativeDispatcher");
    CHECK_NULL(dispatch_class);
    dp_statx_supported = (*env)->GetStaticFieldID(env, dispatch_class, "supports_statx", "Z");
    CHECK_NULL(dp_statx_supported);

    my_statx_func = (statx_func*) dlsym(RTLD_DEFAULT, "statx");
    if (my_statx_func != NULL) {
        // set statx support for Java
        (*env)->SetStaticBooleanField(env, dispatch_class, dp_statx_supported, JNI_TRUE);
        // Load field ids for later access at runtime
        attr_class = (*env)->FindClass(env, "sun/nio/fs/LinuxFileAttributes");
        CHECK_NULL(attr_class);
        attrs_stx_btime_nsec = (*env)->GetFieldID(env, attr_class, "stx_birthtime_nsec", "J");
        CHECK_NULL(attrs_stx_btime_nsec);
        u_attr_class = (*env)->FindClass(env, "sun/nio/fs/UnixFileAttributes");
        CHECK_NULL(u_attr_class);
        attrs_st_mode = (*env)->GetFieldID(env, u_attr_class, "st_mode", "I");
        CHECK_NULL(attrs_st_mode);
        attrs_st_ino = (*env)->GetFieldID(env, u_attr_class, "st_ino", "J");
        CHECK_NULL(attrs_st_ino);
        attrs_st_dev = (*env)->GetFieldID(env, u_attr_class, "st_dev", "J");
        CHECK_NULL(attrs_st_dev);
        attrs_st_rdev = (*env)->GetFieldID(env, u_attr_class, "st_rdev", "J");
        CHECK_NULL(attrs_st_rdev);
        attrs_st_nlink = (*env)->GetFieldID(env, u_attr_class, "st_nlink", "I");
        CHECK_NULL(attrs_st_nlink);
        attrs_st_uid = (*env)->GetFieldID(env, u_attr_class, "st_uid", "I");
        CHECK_NULL(attrs_st_uid);
        attrs_st_gid = (*env)->GetFieldID(env, u_attr_class, "st_gid", "I");
        CHECK_NULL(attrs_st_gid);
        attrs_st_size = (*env)->GetFieldID(env, u_attr_class, "st_size", "J");
        CHECK_NULL(attrs_st_size);
        attrs_st_atime_sec = (*env)->GetFieldID(env, u_attr_class, "st_atime_sec", "J");
        CHECK_NULL(attrs_st_atime_sec);
        attrs_st_atime_nsec = (*env)->GetFieldID(env, u_attr_class, "st_atime_nsec", "J");
        CHECK_NULL(attrs_st_atime_nsec);
        attrs_st_mtime_sec = (*env)->GetFieldID(env, u_attr_class, "st_mtime_sec", "J");
        CHECK_NULL(attrs_st_mtime_sec);
        attrs_st_mtime_nsec = (*env)->GetFieldID(env, u_attr_class, "st_mtime_nsec", "J");
        CHECK_NULL(attrs_st_mtime_nsec);
        attrs_st_ctime_sec = (*env)->GetFieldID(env, u_attr_class, "st_ctime_sec", "J");
        CHECK_NULL(attrs_st_ctime_sec);
        attrs_st_ctime_nsec = (*env)->GetFieldID(env, u_attr_class, "st_ctime_nsec", "J");
        CHECK_NULL(attrs_st_ctime_nsec);
        attrs_st_birthtime_sec = (*env)->GetFieldID(env, u_attr_class, "st_birthtime_sec", "J");
        CHECK_NULL(attrs_st_birthtime_sec);
    }

    my_copy_file_range_func =
        (copy_file_range_func*) dlsym(RTLD_DEFAULT, "copy_file_range");
}

JNIEXPORT jlong JNICALL
Java_sun_nio_fs_LinuxNativeDispatcher_setmntent0(JNIEnv* env, jclass this, jlong pathAddress,
                                                 jlong modeAddress)
{
    FILE* fp = NULL;
    const char* path = (const char*)jlong_to_ptr(pathAddress);
    const char* mode = (const char*)jlong_to_ptr(modeAddress);

    do {
        fp = setmntent(path, mode);
    } while (fp == NULL && errno == EINTR);
    if (fp == NULL) {
        throwUnixException(env, errno);
    }
    return ptr_to_jlong(fp);
}

JNIEXPORT jint JNICALL
Java_sun_nio_fs_LinuxNativeDispatcher_getmntent0(JNIEnv* env, jclass this,
    jlong value, jobject entry, jlong buffer, jint bufLen)
{
    struct mntent ent;
    char * buf = (char*)jlong_to_ptr(buffer);
    struct mntent* m;
    FILE* fp = jlong_to_ptr(value);
    jsize len;
    jbyteArray bytes;
    char* name;
    char* dir;
    char* fstype;
    char* options;

    m = getmntent_r(fp, &ent, buf, (int)bufLen);
    if (m == NULL)
        return -1;
    name = m->mnt_fsname;
    dir = m->mnt_dir;
    fstype = m->mnt_type;
    options = m->mnt_opts;

    len = strlen(name);
    bytes = (*env)->NewByteArray(env, len);
    if (bytes == NULL)
        return -1;
    (*env)->SetByteArrayRegion(env, bytes, 0, len, (jbyte*)name);
    (*env)->SetObjectField(env, entry, entry_name, bytes);

    len = strlen(dir);
    bytes = (*env)->NewByteArray(env, len);
    if (bytes == NULL)
        return -1;
    (*env)->SetByteArrayRegion(env, bytes, 0, len, (jbyte*)dir);
    (*env)->SetObjectField(env, entry, entry_dir, bytes);

    len = strlen(fstype);
    bytes = (*env)->NewByteArray(env, len);
    if (bytes == NULL)
        return -1;
    (*env)->SetByteArrayRegion(env, bytes, 0, len, (jbyte*)fstype);
    (*env)->SetObjectField(env, entry, entry_fstype, bytes);

    len = strlen(options);
    bytes = (*env)->NewByteArray(env, len);
    if (bytes == NULL)
        return -1;
    (*env)->SetByteArrayRegion(env, bytes, 0, len, (jbyte*)options);
    (*env)->SetObjectField(env, entry, entry_options, bytes);

    return 0;
}

JNIEXPORT void JNICALL
Java_sun_nio_fs_LinuxNativeDispatcher_endmntent(JNIEnv* env, jclass this, jlong stream)
{
    FILE* fp = jlong_to_ptr(stream);
    // The endmntent() function always returns 1.
    endmntent(fp);
}

/**
 * Copy statx members into sun.nio.fs.UnixFileAttributes
 */
static void copy_statx_attributes(JNIEnv* env, struct statx* buf, jobject attrs) {
    (*env)->SetIntField(env, attrs, attrs_st_mode, (jint)buf->stx_mode);
    (*env)->SetLongField(env, attrs, attrs_st_ino, (jlong)buf->stx_ino);
    (*env)->SetIntField(env, attrs, attrs_st_nlink, (jint)buf->stx_nlink);
    (*env)->SetIntField(env, attrs, attrs_st_uid, (jint)buf->stx_uid);
    (*env)->SetIntField(env, attrs, attrs_st_gid, (jint)buf->stx_gid);
    (*env)->SetLongField(env, attrs, attrs_st_size, (jlong)buf->stx_size);
    (*env)->SetLongField(env, attrs, attrs_st_atime_sec, (jlong)buf->stx_atime.tv_sec);
    (*env)->SetLongField(env, attrs, attrs_st_mtime_sec, (jlong)buf->stx_mtime.tv_sec);
    (*env)->SetLongField(env, attrs, attrs_st_ctime_sec, (jlong)buf->stx_ctime.tv_sec);
    (*env)->SetLongField(env, attrs, attrs_st_birthtime_sec, (jlong)buf->stx_btime.tv_sec);
    (*env)->SetLongField(env, attrs, attrs_stx_btime_nsec, (jlong)buf->stx_btime.tv_nsec);
    (*env)->SetLongField(env, attrs, attrs_st_atime_nsec, (jlong)buf->stx_atime.tv_nsec);
    (*env)->SetLongField(env, attrs, attrs_st_mtime_nsec, (jlong)buf->stx_mtime.tv_nsec);
    (*env)->SetLongField(env, attrs, attrs_st_ctime_nsec, (jlong)buf->stx_ctime.tv_nsec);
    // convert statx major:minor to dev_t using makedev
    dev_t dev = makedev(buf->stx_dev_major, buf->stx_dev_minor);
    dev_t rdev = makedev(buf->stx_rdev_major, buf->stx_rdev_minor);
    (*env)->SetLongField(env, attrs, attrs_st_dev, (jlong)dev);
    (*env)->SetLongField(env, attrs, attrs_st_rdev, (jlong)rdev);
}

JNIEXPORT jint JNICALL
Java_sun_nio_fs_LinuxNativeDispatcher_statx0(JNIEnv* env, jclass this,
    jlong pathAddress, jobject attrs, jboolean follow_links)
{
    int err = 0;
    struct statx statx_buf;
    int flags = AT_STATX_SYNC_AS_STAT;
    unsigned int mask = STATX_ALL;
    int f_symlink = FOLLOW_SYMLINK;
    const char* path = (const char*)jlong_to_ptr(pathAddress);

    if (my_statx_func != NULL) {
        if (follow_links == JNI_FALSE) {
            f_symlink = NO_FOLLOW_SYMLINK;
        }
        RESTARTABLE(statx_wrapper(AT_FDCWD, path, flags, mask, &statx_buf, f_symlink), err);
        if (err == 0) {
            copy_statx_attributes(env, &statx_buf, attrs);
            return 0;
        } else {
            return errno;
        }
    } else {
        // Do nothing, when statx is not supported. The Java code should
        // use stat64 via UnixNativeDispatcher instead
        return 0;
    }
}

JNIEXPORT jint JNICALL
Java_sun_nio_fs_LinuxNativeDispatcher_statxfd0(JNIEnv* env, jclass this,
    jint fd, jobject attrs)
{
    int err = 0;
    struct statx statx_buf;
    int flags = AT_EMPTY_PATH | AT_STATX_SYNC_AS_STAT;
    unsigned int mask = STATX_ALL;

    if (my_statx_func != NULL) {
        // statx supports FD use via dirfd iff pathname is an empty string and the
        // AT_EMPTY_PATH flag is specified in flags
        RESTARTABLE(statx_wrapper((int)fd, "", flags, mask, &statx_buf, FOLLOW_SYMLINK), err);
        if (err == 0) {
            copy_statx_attributes(env, &statx_buf, attrs);
            return 0;
        } else {
            return errno;
        }
    } else {
        // Do nothing, when statx is not supported. The Java code should
        // use stat64 via UnixNativeDispatcher instead
        return 0;
    }
}

JNIEXPORT jint JNICALL
Java_sun_nio_fs_LinuxNativeDispatcher_posix_1fadvise(JNIEnv* env, jclass this,
    jint fd, jlong offset, jlong len, jint advice)
{
    return posix_fadvise64((int)fd, (off64_t)offset, (off64_t)len, (int)advice);
}

// Copy all bytes from src to dst, within the kernel if possible,
// and return zero, otherwise return the appropriate status code.
//
// Return value
//   0 on success
//   IOS_UNAVAILABLE if the platform function would block
//   IOS_UNSUPPORTED_CASE if the call does not work with the given parameters
//   IOS_UNSUPPORTED if direct copying is not supported on this platform
//   IOS_THROWN if a Java exception is thrown
//
JNIEXPORT jint JNICALL
Java_sun_nio_fs_LinuxNativeDispatcher_directCopy0
    (JNIEnv* env, jclass this, jint dst, jint src, jlong cancelAddress)
{
    volatile jint* cancel = (jint*)jlong_to_ptr(cancelAddress);

    // Transfer within the kernel
    const size_t count = cancel != NULL ?
        1048576 :   // 1 MB to give cancellation a chance
        0x7ffff000; // maximum number of bytes that sendfile() can transfer

    ssize_t bytes_sent;
    if (my_copy_file_range_func != NULL) {
        do {
            RESTARTABLE(my_copy_file_range_func(src, NULL, dst, NULL, count, 0),
                                                bytes_sent);
            if (bytes_sent < 0) {
                switch (errno) {
                    case EINVAL:
                    case ENOSYS:
                    case EXDEV:
                        // ignore and try sendfile()
                        break;
                    default:
                        JNU_ThrowIOExceptionWithLastError(env, "Copy failed");
                        return IOS_THROWN;
                }
            }
            if (cancel != NULL && *cancel != 0) {
                throwUnixException(env, ECANCELED);
                return IOS_THROWN;
            }
        } while (bytes_sent > 0);

        if (bytes_sent == 0)
            return 0;
    }

    do {
        RESTARTABLE(sendfile64(dst, src, NULL, count), bytes_sent);
        if (bytes_sent < 0) {
            if (errno == EAGAIN)
                return IOS_UNAVAILABLE;
            if (errno == EINVAL || errno == ENOSYS)
                return IOS_UNSUPPORTED_CASE;
            throwUnixException(env, errno);
            return IOS_THROWN;
        }
        if (cancel != NULL && *cancel != 0) {
            throwUnixException(env, ECANCELED);
            return IOS_THROWN;
        }
    } while (bytes_sent > 0);

    return 0;
}
