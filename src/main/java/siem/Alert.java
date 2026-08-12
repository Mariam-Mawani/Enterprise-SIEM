package java.siem;
// A simple data class that holds the information for ONE
// security alert raised by our detection engine.

public class Alert {

    public String timestamp;
    public String severity;
    public String description;

    public Alert(String timestamp, String severity, String description) {
        this.timestamp = timestamp;
        this.severity = severity;
        this.description = description;
    }
}
