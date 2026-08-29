package java.siem;

import java.time.LocalDateTime;

public class DetectionEngineTest {

    // Helper method: creates a fake AUTH_FAILED LogEvent.
    // We use this in multiple tests so we write it once here.
    private LogEvent makeFakeFailedLogin(String ipAddress, LocalDateTime time) {
        return new LogEvent(
                time.toString(),    // Raw timestamp
                time,
                "AUTH_FAILED",      // Event type
                ipAddress,
                "user=testuser"     // Extra details
        );
    }




}
