/*
 * Copyright (c) 2023, Red Hat, Inc.
 *
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
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

import java.io.*;
import java.io.Serializable;
import java.lang.reflect.Method;
import java.nio.CharBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import sun.security.jca.GetInstance;

import jdk.test.lib.process.Proc;
import jdk.test.lib.util.FileUtils;

/*
 * @test
 * @bug 8315487
 * @summary
 *   Tests the sun.security.jca.ProvidersFilter.
 * @modules java.base/sun.security.jca
 * @library /test/lib
 * @run main/othervm/timeout=600 -enablesystemassertions ProvidersFilterTest
 */

public final class ProvidersFilterTest {
    private static final boolean DEBUG = false;

    private static final String SEC_FILTER_PROP =
            "jdk.security.providers.filter";

    private static final String FILTER_EXCEPTION_HDR = " * Filter string: ";

    private static final String FILTER_EXCEPTION_MORE = "(...)";

    private static final int FILTER_EXCEPTION_MAX_LINE = 80;

    private static Path workspace;

    private static final String TEST_SERVICE_TYPE = "TestServiceType";

    /*
     * Class used as a service SPI for services added by security providers
     * installed dynamically.
     */
    public static final class TestServiceSpi {
    }

    @FunctionalInterface
    private interface CryptoChecker {
        boolean check(ServiceData svcData);
    }

    @FunctionalInterface
    private interface CryptoOp {
        void doOp() throws Throwable;
    }

    private static boolean cryptoCheck(CryptoOp cryptoOp) {
        try {
            cryptoOp.doOp();
            return true;
        } catch (Throwable t) {
            if (DEBUG) {
                t.printStackTrace();
            }
            return false;
        }
    }

    private static final Map<String, CryptoChecker> cryptoCheckers =
            new HashMap<>();

    static {
        cryptoCheckers.put("Cipher", (ServiceData d) -> cryptoCheck(
                () -> Cipher.getInstance(d.svcAlgo, d.provider)));
        cryptoCheckers.put("Signature", (ServiceData d) -> cryptoCheck(
                () -> Signature.getInstance(d.svcAlgo, d.provider)));
        cryptoCheckers.put("KeyGenerator", (ServiceData d) -> cryptoCheck(
                () -> KeyGenerator.getInstance(d.svcAlgo, d.provider)));
        cryptoCheckers.put(TEST_SERVICE_TYPE,
                (ServiceData d) -> cryptoCheck(() -> GetInstance.getInstance(
                        TEST_SERVICE_TYPE, TestServiceSpi.class, d.svcAlgo,
                        d.provider)));
    }

    private static sealed class ServiceData implements Serializable
            permits DynamicServiceData {
        @Serial
        private static final long serialVersionUID = -351065619007499507L;
        protected final String provider;
        private final String svcType;
        protected final String svcAlgo;

        private ServiceData(String provider, String svcType, String svcAlgo) {
            this.provider = provider;
            this.svcType = svcType;
            this.svcAlgo = svcAlgo;
        }

        @Override
        public String toString() {
            return provider + " / " + svcType + " / " + svcAlgo;
        }
    }

    private static final class DynamicServiceData extends ServiceData {
        @Serial
        private static final long serialVersionUID = 6156428473910912042L;
        final List<String> aliases;
        final Boolean legacy;

        DynamicServiceData(String provider, String svcType,
                String svcAlgo, List<String> aliases, Boolean legacy) {
            super(provider, svcType, svcAlgo);
            if (aliases != null) {
                this.aliases = aliases;
            } else {
                this.aliases = List.of();
            }
            this.legacy = legacy;
        }

        @Override
        public String toString() {
            return super.toString() + (aliases != null ?
                    " / aliases: " + aliases : "") + " / legacy: " + (legacy ==
                    null ? "unregistered" : legacy);
        }
    }

    private record ExpectedExceptionData(String exceptionClass,
            String filterLine, String underliningLine) implements Serializable {
    }

    private static final class TestExecutor {
        enum FilterPropertyType {
            SYSTEM, SECURITY
        }

        @FunctionalInterface
        private interface AssertionDataLoader {
            void apply(TestExecutor testExecutor, String provider,
                    String svcType, String svcAlgo) throws Throwable;
        }

        private final List<DynamicServiceData> dynamicServices =
                new ArrayList<>();
        private final List<ServiceData> expected = new ArrayList<>();
        private final List<ServiceData> notExpected = new ArrayList<>();
        private ExpectedExceptionData expectedException = null;
        private String filterStr;
        private FilterPropertyType propertyType;

        void setFilter(String filterStr) {
            setFilter(filterStr, FilterPropertyType.SECURITY);
        }

        void setFilter(String filterStr, FilterPropertyType propertyType) {
            if (propertyType == FilterPropertyType.SECURITY) {
                StringBuilder sb = new StringBuilder(filterStr.length());
                CharBuffer cb = CharBuffer.wrap(filterStr);
                while (cb.hasRemaining()) {
                    char c = cb.get();
                    if (c == '\\') {
                        sb.append('\\');
                    }
                    if (Character.UnicodeBlock.of(c) ==
                            Character.UnicodeBlock.BASIC_LATIN) {
                        sb.append(c);
                    } else {
                        sb.append("\\u%04x".formatted((int) c));
                    }
                }
                this.filterStr = sb.toString();
            } else {
                this.filterStr = filterStr;
            }
            this.propertyType = propertyType;
            if (DEBUG) {
                System.out.println("Filter: " + filterStr);
            }
        }

        private void addDynamicService(String provider, String svcAlgo,
                List<String> aliases, Boolean legacy,
                AssertionDataLoader assertionDataLoader) throws Throwable {
            DynamicServiceData svcData = new DynamicServiceData(provider,
                    TEST_SERVICE_TYPE, svcAlgo, aliases, legacy);
            dynamicServices.add(svcData);
            // Sanity check: install the dynamic security provider without a
            // filter.
            DynamicProvider dynamicProvider = DynamicProvider.install(svcData);
            dynamicProvider.putAlgo(svcData);
            assertionDataLoader.apply(this, provider, TEST_SERVICE_TYPE,
                    svcAlgo);
        }

        void addExpectedDynamicService(String provider, String svcAlgo)
                throws Throwable {
            addExpectedDynamicService(provider, svcAlgo, null, false);
        }

        void addExpectedDynamicService(String provider, String svcAlgo,
                List<String> aliases, Boolean legacy) throws Throwable {
            addDynamicService(provider, svcAlgo, aliases, legacy,
                    TestExecutor::addExpectedService);
        }

        void addExpectedService(String provider, String svcType,
                String svcAlgo) throws Throwable {
            expected.add(checkSvcAvailable(new ServiceData(provider,
                    svcType, svcAlgo)));
        }

        void addNotExpectedDynamicService(String provider, String svcAlgo)
                throws Throwable {
            addNotExpectedDynamicService(provider, svcAlgo, null, false);
        }

        void addNotExpectedDynamicService(String provider, String svcAlgo,
                List<String> aliases, Boolean legacy) throws Throwable {
            addDynamicService(provider, svcAlgo, aliases, legacy,
                    TestExecutor::addNotExpectedService);
        }

        void addNotExpectedService(String provider, String svcType,
                String svcAlgo) throws Throwable {
            notExpected.add(checkSvcAvailable(new ServiceData(provider,
                    svcType, svcAlgo)));
        }

        /*
         * Sanity check: services must be available without a filter.
         */
        private ServiceData checkSvcAvailable(ServiceData svcData)
                throws Throwable {
            if (!cryptoCheckers.get(svcData.svcType).check(svcData)) {
                throw new Exception("The service " + svcData + " is not" +
                        " available without a filter.");
            }
            return svcData;
        }

        void addExpectedFilterException(String filterLine,
                int underliningSpaces) {
            String underliningLine = " ".repeat(underliningSpaces) +
                    "---^---";
            underliningLine = underliningLine.substring(0, Math.min(
                    underliningLine.length(), FILTER_EXCEPTION_MAX_LINE));
            expectedException = new ExpectedExceptionData("sun.security.jca" +
                    ".ProvidersFilter$Filter$ParserException",
                    FILTER_EXCEPTION_HDR + filterLine, underliningLine);
        }

        void execute() throws Throwable {
            String testClassName = getClass().getEnclosingClass().getName();
            Path dynamicServicesPath = getSvcDataFile(dynamicServices,
                    "Dynamically installed services");
            Path expectedPath = getSvcDataFile(expected, "Expected");
            Path notExpectedPath = getSvcDataFile(notExpected, "Not expected");
            Path expectedExceptionPath = serializeObject(expectedException);
            if (DEBUG) {
                System.out.println("=========================================");
            }
            Proc p = Proc.create(testClassName).args(
                    dynamicServicesPath.toString(), expectedPath.toString(),
                    notExpectedPath.toString(), (expectedExceptionPath == null ?
                            "" : expectedExceptionPath.toString()));
            p.env("JDK_JAVA_OPTIONS", "-enablesystemassertions");
            if (propertyType == FilterPropertyType.SECURITY) {
                p.secprop(SEC_FILTER_PROP, filterStr);
            } else {
                p.prop(SEC_FILTER_PROP, filterStr);
            }
            if (DEBUG) {
                p.inheritIO();
                p.prop("java.security.debug", "jca");
                p.debug(testClassName);

                // Need the launched process to connect to a debugger?
                //System.setProperty("test.vm.opts", "-Xdebug -Xrunjdwp:" +
                //        "transport=dt_socket,address=localhost:8000," +
                //        "suspend=y");
            } else {
                p.nodump();
            }
            p.start().waitFor(0);
            for (ServiceData svcData : dynamicServices) {
                Security.removeProvider(svcData.provider);
            }
        }
    }

    private static Path getSvcDataFile(Object svcData, String title)
            throws Throwable {
        assert svcData != null : "Service data cannot be null.";
        Path svcDataFilePath = serializeObject(svcData);
        showFileContent(svcDataFilePath, title);
        return svcDataFilePath;
    }

    private static List<ServiceData> getSvcData(Path svcDataPath)
            throws Throwable {
        return (List<ServiceData>) deserializeObject(svcDataPath);
    }

    private static Path serializeObject(Object obj) throws Throwable {
        if (obj == null) {
            return null;
        }
        Path objFilePath = Files.createTempFile(workspace, null, null);
        try (FileOutputStream fos =
                     new FileOutputStream(objFilePath.toFile())) {
            ObjectOutputStream oos = new ObjectOutputStream(fos);
            oos.writeObject(obj);
            oos.flush();
        }
        return objFilePath;
    }

    private static Object deserializeObject(Path filePath)
            throws Throwable {
        try (FileInputStream fos = new FileInputStream(filePath.toFile())) {
            ObjectInputStream ois = new ObjectInputStream(fos);
            return ois.readObject();
        }
    }

    private static void showFileContent(Path filePath, String title)
            throws Throwable {
        if (DEBUG) {
            System.out.println("-----------------------------------------");
            System.out.println(title + " assertion data (" + filePath + "):");
            for (ServiceData svcData : getSvcData(filePath)) {
                System.out.println(svcData);
            }
        }
    }

    public static void main(String[] args) throws Throwable {
        if (args.length == 4) {
            // Executed by a child process.
            mainChild(args[0], args[1], args[2], args[3]);
        } else if (args.length == 0) {
            // Executed by the parent process.
            try {
                workspace = Files.createTempDirectory(null);
                mainLauncher();
            } finally {
                FileUtils.deleteFileTreeWithRetry(workspace);
            }
            System.out.println("TEST PASS - OK");
        } else {
            throw new Exception("Unexpected number of arguments.");
        }
    }

    private interface SvcDataConsumer {
        void consume(ServiceData data, boolean available) throws Throwable;
    }

    private static void mainChild(String dynamicServicesPath,
            String expectedPropsPath, String notExpectedPropsPath,
            String expectedExceptionPath) throws Throwable {
        if (!expectedExceptionPath.isEmpty()) {
            ExpectedExceptionData expectedException = (ExpectedExceptionData)
                    deserializeObject(Paths.get(expectedExceptionPath));
            try {
                // Force the filter to be loaded.
                Security.getProviders();
            } catch (Throwable t) {
                if (DEBUG) {
                    System.out.println("Filter line expected: " +
                            expectedException.filterLine);
                    System.out.println("Filter underlining line expected: " +
                            expectedException.underliningLine);
                    t.printStackTrace();
                }
                Throwable ultimateCause = t.getCause();
                while (ultimateCause.getCause() != null) {
                    ultimateCause = ultimateCause.getCause();
                }
                if (ultimateCause.getClass().getName()
                        .equals(expectedException.exceptionClass)) {
                    String[] lines = ultimateCause.getMessage().split("\\R");
                    for (int i = 0; i < lines.length; i++) {
                        if (lines[i].startsWith(FILTER_EXCEPTION_HDR)) {
                            if (lines[i].equals(expectedException.filterLine) &&
                                i < lines.length - 1 && lines[i + 1].equals(
                                        expectedException.underliningLine)) {
                                return;
                            }
                            break;
                        }
                    }
                }
            }
            throw new Exception("Expected filter exception could not be " +
                    "verified.");
        }
        installDynamicServices(dynamicServicesPath);
        if (DEBUG) {
            System.out.println("Security Providers installed:");
            for (Provider provider : Security.getProviders()) {
                System.out.println("Provider: " + provider);
            }
        }
        perSvcDataDo(expectedPropsPath,
                (ServiceData data, boolean available) -> {
            if (!available) {
                throw new Exception("The service '" + data + "' is not " +
                        "available when it was expected.");
            }
        });
        perSvcDataDo(notExpectedPropsPath,
                (ServiceData data, boolean available) -> {
            if (available) {
                throw new Exception("The service '" + data + "' is " +
                        "available when it was not expected.");
            }
        });
    }

    private static abstract sealed class DynamicProvider extends Provider
            permits DynamicProviderCurrent, DynamicProviderLegacy,
            DynamicProviderUnregistered {
        @Serial
        private static final long serialVersionUID = 6088341396620902983L;

        static DynamicProvider install(DynamicServiceData svcData)
                throws Throwable {
            DynamicProvider dynamicProvider;
            if (Security.getProvider(svcData.provider)
                    instanceof DynamicProvider dP) {
                dynamicProvider = dP;
            } else {
                if (svcData.legacy == null) {
                    dynamicProvider = new DynamicProviderUnregistered(svcData);
                } else if (svcData.legacy) {
                    dynamicProvider = new DynamicProviderLegacy(svcData);
                } else {
                    dynamicProvider = new DynamicProviderCurrent(svcData);
                }
                if (Security.addProvider(dynamicProvider) == -1) {
                    throw new Exception("Could not install dynamic provider.");
                }
            }
            return dynamicProvider;
        }

        DynamicProvider(ServiceData svcData) {
            super(svcData.provider, "", svcData.toString());
        }
        abstract void putAlgo(DynamicServiceData svcData);
    }

    private static final class DynamicProviderCurrent extends DynamicProvider {
        @Serial
        private static final long serialVersionUID = 7754296009615868997L;

        DynamicProviderCurrent(DynamicServiceData svcData) {
            super(svcData);
        }

        @Override
        void putAlgo(DynamicServiceData svcData) {
            putService(new Service(this, TEST_SERVICE_TYPE, svcData.svcAlgo,
                    TestServiceSpi.class.getName(), svcData.aliases, null));
        }
    }

    private static final class DynamicProviderLegacy extends DynamicProvider {
        @Serial
        private static final long serialVersionUID = 1859892951118353404L;

        DynamicProviderLegacy(DynamicServiceData svcData) {
            super(svcData);
        }

        @Override
        void putAlgo(DynamicServiceData svcData) {
            put(TEST_SERVICE_TYPE + "." + svcData.svcAlgo,
                    TestServiceSpi.class.getName());
            for (String alias : svcData.aliases) {
                put("Alg.Alias." + TEST_SERVICE_TYPE + "." + alias,
                        svcData.svcAlgo);
            }
        }
    }

    private static final class DynamicProviderUnregistered
            extends DynamicProvider {
        @Serial
        private static final long serialVersionUID = 4421847184357342760L;
        private final Map<String, Service> services = new HashMap<>();

        DynamicProviderUnregistered(DynamicServiceData svcData) {
            super(svcData);
        }

        @Override
        void putAlgo(DynamicServiceData svcData) {
            Provider.Service s = new Service(this, TEST_SERVICE_TYPE,
                    svcData.svcAlgo, TestServiceSpi.class.getName(),
                    svcData.aliases, null);
            services.put(s.getType() + "." + s.getAlgorithm(), s);
            for (String alias : svcData.aliases) {
                services.put(s.getType() + "." + alias, s);
            }
        }

        @Override
        public Provider.Service getService(String type, String algorithm) {
            return services.get(type + "." + algorithm);
        }

        @Override
        public Set<Provider.Service> getServices() {
            return new HashSet<>(services.values());
        }
    }

    private static void installDynamicServices(String svcDataPath)
            throws Throwable {
        for (ServiceData svcDataObj : getSvcData(Paths.get(svcDataPath))) {
            DynamicServiceData svcData = (DynamicServiceData)svcDataObj;
            DynamicProvider dynamicProvider = DynamicProvider.install(svcData);
            dynamicProvider.putAlgo(svcData);
        }
    }

    private static void perSvcDataDo(String svcDataPath,
            SvcDataConsumer svcDataDo) throws Throwable {
        for (ServiceData svcData : getSvcData(Paths.get(svcDataPath))) {
            CryptoChecker checker = cryptoCheckers.get(svcData.svcType);
            boolean availableInCryptoCheckers = checker.check(svcData);
            List<String> allAlgos = new ArrayList<>(List.of(svcData.svcAlgo));
            if (svcData instanceof DynamicServiceData dynamicSvcData) {
                allAlgos.addAll(dynamicSvcData.aliases);
            }
            for (String algo : allAlgos) {
                String filter = svcData.svcType + "." + algo;
                boolean availableInFiltered = findSvcInFilteredProviders(
                        svcData.provider, filter);
                if (availableInCryptoCheckers != availableInFiltered) {
                    throw new Exception("Inconsistent Security.getProviders(" +
                            "\"" + filter + "\") filtering result.");
                }
            }
            svcDataDo.consume(svcData, availableInCryptoCheckers);
        }
    }

    private static boolean findSvcInFilteredProviders(String provider,
            String filter) {
        Provider[] filteredProviders = Security.getProviders(filter);
        if (filteredProviders != null) {
            for (Provider p : filteredProviders) {
                if (p.getName().equals(provider)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static void mainLauncher() throws Throwable {
        for (Method m : ProvidersFilterTest.class.getDeclaredMethods()) {
            if (m.getName().startsWith("test")) {
                printTestHeader(m.getName());
                TestExecutor t = new TestExecutor();
                m.invoke(null, t);
                t.execute();
            }
        }
    }

    private static void printTestHeader(String testName) {
        if (DEBUG) {
            System.out.println("=========================================");
            System.out.println(testName);
            System.out.println("-----------------------------------------");
        }
    }

    /*
     * Valid filters
     */

    private static void testBasicFiltering(TestExecutor t) throws Throwable {
        t.setFilter("  SunJCE.Cipher.AES  ;  !  *.*.*WeaK*;" +
                "MyProvider.*.myStrongAlgorithm*; !NonExistentProvider  ");
        t.addExpectedService("SunJCE", "Cipher", "AES");
        t.addExpectedDynamicService("MyProvider", "MyStrongAlgorithm");
        t.addExpectedDynamicService("MyProvider", "MyStrongAlgorithm2");
        t.addNotExpectedService("SunJCE", "KeyGenerator", "HmacSHA3-512");
        t.addNotExpectedDynamicService("MyProvider", "MyWeakAlgorithm");
    }

    private static void testBasicFilteringUnregistered(TestExecutor t)
            throws Throwable {
        t.setFilter("R1_MyProvider.*.strong; !R1_MyProvider;" +
                "!R2_MyProvider.*.weak; R2_MyProvider");
        t.addExpectedDynamicService("R1_MyProvider", "strong", List.of(), null);
        t.addExpectedDynamicService("R2_MyProvider", "Algo", List.of(), null);
        t.addNotExpectedDynamicService("R1_MyProvider", "Algo", List.of(),
                null);
        t.addNotExpectedDynamicService("R2_MyProvider", "weak", List.of(),
                null);
    }

    private static void testCharsEscaping(TestExecutor t) throws Throwable {
        t.setFilter("R1_\\M\\!\\ \\.Pr\\*\\\\/\\;der \t; " +
                "R2_My\\\\E\\.\\\\QProvider;" +
                "\\!R3_M\\:Pr\\\tvi\\,de\u2014r.*;");
        t.addExpectedDynamicService("R1_M! .Pr*\\/;der", "Algo");
        t.addExpectedDynamicService("R2_My\\E.\\QProvider", "Algo");
        t.addExpectedDynamicService("!R3_M:Pr\tvi,de\u2014r", "Algo");
        t.addNotExpectedDynamicService("R1_\\M! .Pr*\\/;der", "Algo");
        t.addNotExpectedDynamicService("R1_M! .Pro\\/;der", "Algo");
        t.addNotExpectedDynamicService("R1_M! .Pr*/;der", "Algo");
        t.addNotExpectedDynamicService("R1_M! .Pr*\\/", "Algo");
        t.addNotExpectedDynamicService("R1_M! .Pr*\\/\\", "Algo");
        t.addNotExpectedDynamicService("R2_MyXProvider", "Algo");
    }

    private static void testWildcardGreediness(TestExecutor t)
            throws Throwable {
        t.setFilter("R1_MyProvider*; R2_MyProviderA**B**C; " +
                "R3_MyProvider*ABC");
        t.addExpectedDynamicService("R1_MyProvider", "Algo");
        t.addExpectedDynamicService("R1_MyProviderX", "Algo");
        t.addExpectedDynamicService("R1_MyProviderXX", "Algo");
        t.addExpectedDynamicService("R2_MyProviderABC", "Algo");
        t.addExpectedDynamicService("R2_MyProviderABCDC", "Algo");
        t.addExpectedDynamicService("R2_MyProviderABCCCC", "Algo");
        t.addExpectedDynamicService("R3_MyProviderABC", "Algo");
        t.addExpectedDynamicService("R3_MyProviderABCABC", "Algo");
        t.addNotExpectedDynamicService("R2_MyProviderA", "Algo");
    }

    private static void testLeftPrecedence(TestExecutor t) throws Throwable {
        t.setFilter("R1_MyProvider; !R1_MyProvider; !R2_MyProvider; " +
                "R2_MyProvider; !R3_*; R3_MyProvider; !R4_*.*.AES; " +
                "R4_*.*.RSA");
        t.addExpectedDynamicService("R1_MyProvider", "Algo");
        t.addExpectedDynamicService("R4_MyProvider", "RSA");
        t.addNotExpectedDynamicService("R2_MyProvider", "Algo");
        t.addNotExpectedDynamicService("R3_MyProvider", "Algo");
        t.addNotExpectedDynamicService("R4_MyProvider", "AES");
        t.addNotExpectedDynamicService("R4_MyProvider", "*");
    }

    private static void aliasesCommon(TestExecutor t, Boolean legacy)
            throws Throwable {
        t.setFilter("R1_MyProvider.*.Alias; !R1_MyProvider.*.Algo; " +
                "!R2_MyProvider.*.Alias; R2_MyProvider.*.Algo;" +
                "R3_MyProvider.*.Algo; !R3_MyProvider.*.Alias;" +
                "!R4_MyProvider.*.Algo; R4_MyProvider.*.Alias;" +
                "R5_MyProvider.*.ALIAS1; !R5_MyProvider.*.ALIAS2");
        t.addExpectedDynamicService("R1_MyProvider", "Algo", List.of("Alias"),
                legacy);
        t.addExpectedDynamicService("R3_MyProvider", "Algo", List.of("Alias"),
                legacy);
        t.addExpectedDynamicService("R5_MyProvider", "Algo", List.of("Alias1",
                "Alias2"), legacy);
        t.addNotExpectedDynamicService("R2_MyProvider", "Algo",
                List.of("Alias"), legacy);
        t.addNotExpectedDynamicService("R4_MyProvider", "Algo",
                List.of("Alias"), legacy);
    }

    private static void testAliases(TestExecutor t) throws Throwable {
        aliasesCommon(t, false);
    }

    private static void testAliasesLegacy(TestExecutor t) throws Throwable {
        aliasesCommon(t, true);
    }

    private static void testAliasesUnregistered(TestExecutor t)
            throws Throwable {
        aliasesCommon(t, null);
    }

    /*
     * Invalid filters (must throw an exception)
     */

    private static void testWhitespacesOnlyInFilter(TestExecutor t)
            throws Throwable {
        t.setFilter("\t\t\t", TestExecutor.FilterPropertyType.SYSTEM);
        t.addExpectedFilterException("\t\t\t", 17);
    }

    private static void testWhitespacesOnlyInRule(TestExecutor t) {
        t.setFilter("*;    ;");
        t.addExpectedFilterException("*;    ;", 21);
    }

    private static void testDenyOnly(TestExecutor t) {
        t.setFilter("!");
        t.addExpectedFilterException("!", 15);
    }

    private static void testTooManyLevels(TestExecutor t) {
        t.setFilter("*.*.*.*");
        t.addExpectedFilterException("*.*.*.*", 20);
    }

    private static void testMissingSecurityProvider(TestExecutor t) {
        t.setFilter(".*.*");
        t.addExpectedFilterException(".*.*", 15);
    }

    private static void testDenyMissingSecurityProvider(TestExecutor t) {
        t.setFilter("!.*");
        t.addExpectedFilterException("!.*", 16);
    }

    private static void testMissingServiceType(TestExecutor t) {
        t.setFilter("*.");
        t.addExpectedFilterException("*.", 16);
    }

    private static void testMissingServiceType2(TestExecutor t) {
        t.setFilter("*..*");
        t.addExpectedFilterException("*..*", 17);
    }

    private static void testMissingAlgorithm(TestExecutor t) {
        t.setFilter("*.*.");
        t.addExpectedFilterException("*.*.", 18);
    }

    private static void testUnescapedSpaceInProvider(TestExecutor t) {
        t.setFilter("My Provider");
        t.addExpectedFilterException("My Provider", 18);
    }

    private static void testUnescapedSpaceInServiceType(TestExecutor t) {
        t.setFilter("MyProvider. MyService");
        t.addExpectedFilterException("MyProvider. MyService", 26);
    }

    private static void testUnescapedExclamationMark(TestExecutor t) {
        t.setFilter("My!Provider");
        t.addExpectedFilterException("My!Provider", 17);
    }

    private static void testUnescapedColonInProvider(TestExecutor t) {
        t.setFilter("My:Provider");
        t.addExpectedFilterException("My:Provider", 17);
    }

    private static void testUnescapedCommaInProvider(TestExecutor t) {
        t.setFilter("My,Provider");
        t.addExpectedFilterException("My,Provider", 17);
    }

    private static void testFilterEndsInEscape(TestExecutor t) {
        t.setFilter("\\");
        t.addExpectedFilterException("\\", 15);
    }

    private static void testProviderEndsInEscape(TestExecutor t) {
        t.setFilter("MyProvider\\");
        t.addExpectedFilterException("MyProvider\\", 25);
    }

    private static void testParserExceptionLineMoreRight(TestExecutor t) {
        t.setFilter("." + ";".repeat(FILTER_EXCEPTION_MAX_LINE + 10));
        t.addExpectedFilterException("." + ";".repeat(
                FILTER_EXCEPTION_MAX_LINE - FILTER_EXCEPTION_HDR.length() - 1
                        - FILTER_EXCEPTION_MORE.length() - 1) + " " +
                FILTER_EXCEPTION_MORE, 15);
    }

    private static void testParserExceptionLineMoreLeft(TestExecutor t) {
        t.setFilter("*".repeat(FILTER_EXCEPTION_MAX_LINE + 10) + "!");
        t.addExpectedFilterException(FILTER_EXCEPTION_MORE + " " + "*".repeat(
                FILTER_EXCEPTION_MAX_LINE - FILTER_EXCEPTION_HDR.length() - 1
                        - FILTER_EXCEPTION_MORE.length() - 1) + "!", 76);
    }

    private static void testParserExceptionLineMoreBoth(TestExecutor t) {
        t.setFilter("*".repeat(FILTER_EXCEPTION_MAX_LINE + 10) + "!" +
                "*".repeat(FILTER_EXCEPTION_MAX_LINE + 10));
        float halfWildcards = (FILTER_EXCEPTION_MAX_LINE -
                FILTER_EXCEPTION_HDR.length() - (FILTER_EXCEPTION_MORE.length()
                + 1) * 2 - 1) / 2.0f;
        int preWildcards = (int) halfWildcards;
        int postWildcards = (int) (halfWildcards + 0.5f);
        t.addExpectedFilterException(FILTER_EXCEPTION_MORE + " " + "*".repeat(
                preWildcards) + "!" + "*".repeat(postWildcards) + " " +
                FILTER_EXCEPTION_MORE, 45);
    }
}
