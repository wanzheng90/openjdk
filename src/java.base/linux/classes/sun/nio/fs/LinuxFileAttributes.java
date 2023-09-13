/*
 * Copyright (c) 2023, Red Hat, Inc.
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

package sun.nio.fs;

import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFileAttributes;

class LinuxFileAttributes extends UnixFileAttributes implements PosixFileAttributes {

    private final boolean isStatxSupported;
    private long stx_birthtime_nsec;

    private LinuxFileAttributes(boolean isStatxSupported) {
        this.isStatxSupported = isStatxSupported;
    }

    // get the Linux file attributes for a given file
    static LinuxFileAttributes get(UnixPath path, boolean followLinks) throws UnixException {
        boolean statxSupport = LinuxNativeDispatcher.isStatxSupported();
        LinuxFileAttributes attrs = new LinuxFileAttributes(statxSupport);
        if (statxSupport) {
            LinuxNativeDispatcher.statx(path, attrs, followLinks);
        } else {
            // this sets attribute values in attrs
            UnixFileAttributes.get(path, followLinks, attrs);
        }
        return attrs;
    }

    // get the LinuxFileAttributes for a given file descriptor
    static LinuxFileAttributes get(int fd) throws UnixException {
        boolean statxSupport = LinuxNativeDispatcher.isStatxSupported();
        LinuxFileAttributes attrs = new LinuxFileAttributes(statxSupport);
        if (statxSupport) {
            LinuxNativeDispatcher.statxfd(fd, attrs);
        } else {
            // this sets attribute values in attrs
            UnixFileAttributes.get(fd, attrs);
        }
        return attrs;
    }

    // wrap this object with BasicFileAttributes object to prevent leaking of
    // user information
    BasicFileAttributes asBasicFileAttributes() {
        return UnixAsBasicFileAttributes.wrap(this);
    }

    @Override
    public FileTime creationTime() {
        if (isStatxSupported) {
            return UnixFileAttributes.toFileTime(st_birthtime_sec, stx_birthtime_nsec);
        } else {
            return super.creationTime();
        }
    }
}
