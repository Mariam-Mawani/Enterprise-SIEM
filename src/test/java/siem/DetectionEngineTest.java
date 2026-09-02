package java.siem;

import java.time.LocalDateTime;
import java.util.ArrayList;

public class DetectionEngineTest {

    // Helper method: creates a fake AUTH_FAILED LogEvent.
    // We use this in multiple tests so we write it once here.
    private LogEvent makeFakeFailedLogin(String ipAddress, LocalDateTime time) {
        return new LogEvent(
                time.toString(),    // Raw timestamp
                time,               // Timestamp as localDateTime
                "AUTH_FAILED",      // Event type
                ipAddress,          // Ip address
                "user=testuser"     // Extra details
        );
    }

    // Helper: creates a fake PORT_SCAN_PROBE LogEvent
    private LogEvent makeFakePortProbe(String ipAddress, int port, LocalDateTime time) {
        return new LogEvent(
                time.toString(),
                time,
                "PORT_SCAN_PROBE",
                ipAddress,
                "port=" + port
        );
    }

    // A single failed login should NOT raise an alert.
    // One mistyped password is completely normal. Our rule
    // requires 5+ failures, so 1 failure must produce 0 alerts.
    @Test
    public void oneFailedLoginShouldNotTriggerAlert() {
        ArrayList<LogEvent> events = new ArrayList<>();
        events.add(makeFakeFailedLogin("1.2.3.4", LocalDateTime.now()));

        DetectionEngine engine = new DetectionEngine();
        ArrayList<Alert> alerts = engine.runAllRules(events);

        // assertEquals(expected, actual, message)
        assertEquals(0, alerts.size(), "A single failed login should NOT trigger a brute-force alert");
    }

    // Five failed logins in one minute SHOULD raise a 'HIGH' alert.
    // Our threshold is 5 failures within 5 minutes.
    // Five failures spaced 10 seconds apart (total: 40 seconds)
    // must produce exactly 1 HIGH alert.
    @Test
    public void fiveFailedLoginsInOneMinuteShouldTriggerAlert() {
        ArrayList<LogEvent> events = new ArrayList<>();
        LocalDateTime baseTime = LocalDateTime.now();

        // Add 5 failed logins from the SAME IP, 10 seconds apart
        for (int i = 0; i < 5; i++) {
            events.add(makeFakeFailedLogin("9.9.9.9", baseTime.plusSeconds(i * 10)));
        }

        DetectionEngine engine = new DetectionEngine();
        ArrayList<Alert> alerts = engine.runAllRules(events);

        assertEquals(1, alerts.size(), "Five failed logins from one IP should trigger exactly one brute-force alert");
        assertEquals("HIGH", alerts.get(0).severity, "The brute-force alert should have HIGH severity");
    }

    // Failures from DIFFERENT IPs should not be grouped.
    // Three failures from IP A and three failures from IP B
    // should not combine to trigger an alert. Each IP is
    // checked independently.
    // --------------------------------------------------------
    @Test
    public void failuresFromDifferentIpsShouldNotCombine() {
        ArrayList<LogEvent> events = new ArrayList<>();
        LocalDateTime baseTime = LocalDateTime.now();

        // 3 failures from IP A
        for (int i = 0; i < 3; i++) {
            events.add(makeFakeFailedLogin("10.0.0.1", baseTime.plusSeconds(i * 10)));
        }

        // 3 failures from IP B (still only 3 each, below the threshold of 5)
        for (int i = 0; i < 3; i++) {
            events.add(makeFakeFailedLogin("10.0.0.2", baseTime.plusSeconds(i * 10)));
        }

        DetectionEngine engine = new DetectionEngine();
        ArrayList<Alert> alerts = engine.runAllRules(events);

        assertEquals(0, alerts.size(), "Failures from different IPs must NOT be combined to trigger an alert");
    }

    // Ten port probes from one IP in under a minute, SHOULD raise a 'MEDIUM' alert.
    @Test
    public void tenPortProbesInOneMinuteShouldTriggerAlert() {
        ArrayList<LogEvent> events = new ArrayList<>();
        LocalDateTime baseTime = LocalDateTime.now();

        // Probe 10 different ports, 3 seconds apart (total: 27 seconds)
        int[] ports = {21, 22, 23, 25, 80, 110, 139, 443, 3306, 3389};
        for (int i = 0; i < ports.length; i++) {
            events.add(makeFakePortProbe("5.5.5.5", ports[i], baseTime.plusSeconds(i * 3)));
        }

        DetectionEngine engine = new DetectionEngine();
        ArrayList<Alert> alerts = engine.runAllRules(events);

        assertEquals(1, alerts.size(),
                "Ten port probes in under a minute should trigger exactly one port-scan alert");
        assertEquals("MEDIUM", alerts.get(0).severity,
                "The port-scan alert should have MEDIUM severity");
    }





}
