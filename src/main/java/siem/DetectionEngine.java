package java.siem;

/*
 * This class contains our "detection rules" -- the logic that
 * looks across all the log events and spots suspicious patterns.
 */


import java.util.ArrayList;
import java.util.HashMap;

public class DetectionEngine {

    // Rule thresholds -- change these numbers to make the rules more or less sensitive
    // (this is called "tuning" in real SIEM deployments).

    // Brute-force rule
    private static final int BRUTE_FORCE_LOGIN_THRESHOLD = 5;   // Number of failures
    private static final long BRUTE_FORCE_WINDOW_MINUTES = 5;   // Within this time window
    // Port scan rule
    private static final int PORT_SCAN_PORT_THRESHOLD = 10;     // Number of distinct ports
    private static final long PORT_SCAN_WINDOW_MINUTES = 1;     // Within this time window

    // Public method: run ALL rules and return every alert raised
    public ArrayList<Alert> runAllRules(ArrayList<LogEvent> events) {

        ArrayList<Alert> allAlerts = new ArrayList<>();

        // Rule each and collect whatever allerts it produces
        ArrayList<Alert> bruteForceAlerts = checkForBruteForce(events);
        ArrayList<Alert> portScanAlerts   = checkForPortScan(events);

        allAlerts.addAll(bruteForceAlerts);
        allAlerts.addAll(portScanAlerts);

        System.out.println(" Detection complete. Alerts raised: " + allAlerts.size());
        return allAlerts;
    }

    // Brute force detection
    private ArrayList<Alert> checkForBruteForce(ArrayList<LogEvent> events) {
        ArrayList<Alert> alerts = new ArrayList<>();

        // Group every AUTH_FAILED event by the IP address it came from.
        // We use a HashMap where:
        // key = an IP address string, e.g. "198.51.100.23"
        // value = a list of all AUTH_FAILED LogEvent objects from that IP
        HashMap<String, ArrayList<LogEvent>> failedLoginsByIp = new HashMap<>();

        for (LogEvent event : events) {
            if (event.eventType.equals("AUTH_FAILED")) {
                // If this IP has no entry yet, create an empty list for it first
                if (!failedLoginsByIp.containsKey(event.ipAddress)) {
                    failedLoginsByIp.put(event.ipAddress, new ArrayList<>());
                }
                failedLoginsByIp.get(event.ipAddress).add(event);
            }
        }
    }

}
