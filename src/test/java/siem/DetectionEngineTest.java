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



}
