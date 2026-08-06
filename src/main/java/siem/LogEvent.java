package java.siem;
// A simple data class that holds all the information from
// ONE line in our log file.

import java.time.LocalDateTime;

public class LogEvent {

    public String rawTimeStamp;     // Exactly as it appeared in the log file (text form)
    public LocalDateTime timestamp; // Converted into a LocalDateTime object.
    public String eventType;        // "AUTH_FAILED" or "PORT_SCAN_PROBE"
    public String ipAddress;        // That event came from
    public String extraDetails;     // "user=admin" or "port=22"


    // Called when we do 'new LogEvent()' to fill all the fields
    public LogEvent(String rawTimeStamp, LocalDateTime timestamp, String eventType,
                    String ipAddress, String extraDetails) {
        this.rawTimeStamp = rawTimeStamp;
        this.timestamp = timestamp;
        this.eventType = eventType;
        this.ipAddress = ipAddress;
        this.extraDetails = extraDetails;
    }

    @Override
    public String toString() {
        return "LogEvent{" +
                "rawTimeStamp='" + rawTimeStamp + '\'' +
                ", timestamp=" + timestamp +
                ", eventType='" + eventType + '\'' +
                ", ipAddress='" + ipAddress + '\'' +
                ", extraDetails='" + extraDetails + '\'' +
                '}';
    }
}
