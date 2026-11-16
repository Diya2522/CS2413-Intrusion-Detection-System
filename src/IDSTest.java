import java.io.File;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;


public class IDSTest {
    private static final Instant START = Instant.parse("2026-10-08T10:30:00Z");
    private static final String SOURCE_IP = "192.168.1.10";
    private static final String DESTINATION_IP = "192.168.1.20";
    private static final String CONFIG_FILE = "config/ids.properties";
    private interface TestCase {
        void run() throws Exception;
    }

    public static void runTests() {
        int[] results = {0, 0};

        runTest("Brute-force detection", results, () -> {
            List<SecurityAlert> alerts = BruteForceDetector.detect(failedLoginsAt(0, 10, 20), config(CONFIG_FILE));
            checkEquals(1, alerts.size());
            checkEquals("BRUTE_FORCE", alerts.get(0).getAttackType());
        });

        runTest("Higher brute-force threshold", results, () -> {
            List<NetworkEvent> events = failedLoginsAt(0, 10);
            IDSConfig config = config(CONFIG_FILE);
            checkEquals(0, BruteForceDetector.detect(events, config).size());
            events.add(failedLoginAt(20));
            checkEquals(1, BruteForceDetector.detect(events, config).size());
        });

        runTest("Port-scan detection", results, () -> {
            List<SecurityAlert> alerts = PortScanDetector.detect(connectionsAt(0, 10, 20, 30), config(CONFIG_FILE));
            checkEquals(1, alerts.size());
            checkEquals("PORT_SCAN", alerts.get(0).getAttackType());
        });

        runTest("Higher port-scan threshold", results, () -> {
            List<NetworkEvent> events = connectionsAt(0, 10, 20);
            IDSConfig config = config(CONFIG_FILE);
            checkEquals(0, PortScanDetector.detect(events, config).size());
            events.add(connectionAt(30, 1004));
            checkEquals(1, PortScanDetector.detect(events, config).size());
        });

        runTest("High-traffic detection", results, () -> {
            List<SecurityAlert> alerts = TrafficVolumeDetector.detect(List.of(eventAt(0, "CONNECTION", 10_001, 443)), config(CONFIG_FILE));
            checkEquals(1, alerts.size());
            checkEquals("HIGH_TRAFFIC", alerts.get(0).getAttackType());
        });

        runTest("Higher traffic threshold", results, () -> {
            checkEquals(0, TrafficVolumeDetector.detect(List.of(eventAt(0, "CONNECTION", 9999, 443)), config(CONFIG_FILE)).size());
            checkEquals(1, TrafficVolumeDetector.detect(List.of(eventAt(1, "CONNECTION", 10_000, 443)), config(CONFIG_FILE)).size());
        });

        runTest("Failed logins outside the detection window", results, () ->
            checkEquals(0, BruteForceDetector.detect(failedLoginsAt(0, 61, 122), config(CONFIG_FILE)).size()));

        runTest("Repeated destination ports", results, () -> {
            List<NetworkEvent> events = new ArrayList<>();
            events.add(eventAt(0, "CONNECTION", 100, 22));
            events.add(eventAt(1, "CONNECTION", 100, 22));
            events.add(eventAt(2, "CONNECTION", 100, 22));
            events.add(eventAt(3, "CONNECTION", 100, 80));
            events.add(eventAt(4, "CONNECTION", 100, 443));
            checkEquals(0, PortScanDetector.detect(events, config(CONFIG_FILE)).size());
        });

        runTest("Out-of-order network events", results, () -> {
            List<NetworkEvent> events = new ArrayList<>();
            events.add(failedLoginAt(20));
            events.add(failedLoginAt(0));
            events.add(failedLoginAt(10));
            events.add(connectionAt(30, 1004));
            events.add(connectionAt(0, 1001));
            events.add(connectionAt(20, 1003));
            events.add(connectionAt(10, 1002));

            IDSConfig config = config(CONFIG_FILE);
            List<SecurityAlert> bfAlerts = BruteForceDetector.detect(events, config);
            List<SecurityAlert> psAlerts = PortScanDetector.detect(events, config);
            checkEquals(1, bfAlerts.size());
            checkEquals(START.plusSeconds(20), bfAlerts.get(0).getTimestamp());
            checkEquals(1, psAlerts.size());
            checkEquals(START.plusSeconds(30), psAlerts.get(0).getTimestamp());
        });

        runTest("Duplicate brute-force alert suppression", results, () -> {
            List<SecurityAlert> alerts = BruteForceDetector.detect(failedLoginsAt(0, 5, 10, 15, 20), config(CONFIG_FILE));
            checkEquals(1, alerts.size());
        });

        runTest("Traffic exactly at the configured threshold", results, () -> checkEquals(1, TrafficVolumeDetector.detect(List.of(eventAt(0, "CONNECTION", 10_000, 443)), config(CONFIG_FILE)).size()));

        runTest("Brute-force detection at the exact time boundary", results, () -> {
            List<SecurityAlert> alerts = BruteForceDetector.detect(failedLoginsAt(0, 30, 60), config(CONFIG_FILE));
            checkEquals(1, alerts.size());
            checkEquals(START.plusSeconds(60), alerts.get(0).getTimestamp());
        });

        System.out.println("\n---------- TEST RESULTS ----------");
        System.out.println("Passed: " + results[0]);
        System.out.println("Failed: " + results[1]);
        System.out.println("-----------------------------------\n");
        return;
    }

    private static void runTest(String name, int[] results, TestCase test) {
        try {
            test.run();
            results[0]++;
        } catch (AssertionError | Exception error) {
            results[1]++;
            System.out.println("FAILED: " + name);
            System.out.println("  Reason: " + error.getMessage());
        }
    }

    private static IDSConfig config(String filename) throws IOException {
        File configFile = new File(filename);
        return new IDSConfig(configFile.getPath());
    }

    private static List<NetworkEvent> failedLoginsAt(int... seconds) {
        List<NetworkEvent> events = new ArrayList<>();
        for (int second : seconds) {
            events.add(failedLoginAt(second));
        }
        return events;
    }

    private static List<NetworkEvent> connectionsAt(int... seconds) {
        List<NetworkEvent> events = new ArrayList<>();
        for (int index = 0; index < seconds.length; index++) {
            events.add(connectionAt(seconds[index], 1001 + index));
        }
        return events;
    }

    private static NetworkEvent failedLoginAt(int second) {
        return eventAt(second, "LOGIN_FAIL", 0, 0);
    }

    private static NetworkEvent connectionAt(int second, int destinationPort) {
        return eventAt(second, "CONNECTION", 0, destinationPort);
    }

    private static NetworkEvent eventAt(int second, String eventType,
                                        long bytes, int destinationPort) {
        return new NetworkEvent(START.plusSeconds(second), SOURCE_IP,
                DESTINATION_IP, destinationPort, eventType, bytes);
    }

    private static void checkEquals(Object expected, Object actual) {
        if (!expected.equals(actual)) {
            throw new AssertionError("Expected " + expected + " but was " + actual);
        }
    }

    public static void main(String[] args) {
        runTests();
    }
}