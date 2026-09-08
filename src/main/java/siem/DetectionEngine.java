package java.siem;

/*
 * This class contains our "detection rules" -- the logic that
 * looks across all the log events and spots suspicious patterns.
 */


import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;

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

    // Rule 1: Brute force detection
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
        // Check each IP's failure list against our rule
        for (String ipAddress : failedLoginsByIp.keySet()) {
            ArrayList<LogEvent> failedLogins = failedLoginsByIp.get(ipAddress);
            // Does this IP even meet the minimum count?
            if (failedLogins.size() < BRUTE_FORCE_LOGIN_THRESHOLD) {
                continue;   // not enough failures -- move on to the next IP
            }
            // Find the earliest and latest timestamps in this IP's failure list.
            // The time between those two is the "span" of the activity.
            LogEvent earliest = failedLogins.get(0);
            LogEvent latest = failedLogins.get(0);

            for (LogEvent login : failedLogins) {
                if (login.timestamp.isBefore(earliest.timestamp)) {
                    earliest = login;
                }
                if (login.timestamp.isAfter(latest.timestamp)) {
                    latest = login;
                }
            }
            // Duration.between() gives us the exact time gap.
            // toMinutes() converts that gap into whole minutes.
            long minutesSpanned = Duration.between(earliest.timestamp, latest.timestamp)
                    .toMinutes();
            long secondsSpanned = Duration.between(earliest.timestamp, latest.timestamp)
                    .toSeconds();

            // Did all the failures happen within our allowed time window?
            if (minutesSpanned <= BRUTE_FORCE_WINDOW_MINUTES) {

                String description = "Possible brute-force attack from " + ipAddress
                        + ": " + failedLogins.size() + " failed logins"
                        + " within " + secondsSpanned + " seconds.";

                // Use the timestamp of the LAST failure as the alert time
                alerts.add(new Alert(latest.rawTimestamp, "HIGH", description));
            }
        }
        return alerts;
    }

    // RULE 2: Port Scan Detection
    private ArrayList<Alert> checkForPortScan(ArrayList<LogEvent> events) {

        ArrayList<Alert> alerts = new ArrayList<>();
        // Group every PORT_SCAN_PROBE event by IP address.
        // Same structure as the brute-force rule above.
        HashMap<String, ArrayList<LogEvent>> probesByIp = new HashMap<>();

        for (LogEvent event : events) {
            if (event.eventType.equals("PORT_SCAN_PROBE")) {

                if (!probesByIp.containsKey(event.ipAddress)) {
                    probesByIp.put(event.ipAddress, new ArrayList<>());
                }

                probesByIp.get(event.ipAddress).add(event);
            }
        }
        // Step 2: Check each IP's probe list against our rule
        for (String ipAddress : probesByIp.keySet()) {
            ArrayList<LogEvent> probes = probesByIp.get(ipAddress);

            // We care about DISTINCT ports, not total probe count.
            // Scanning port 22 five times is less suspicious than scanning
            // five different ports once each. We use a HashSet because
            // adding the same value to a HashSet twice still only stores it once.
            HashSet<String> distinctPorts = new HashSet<>();
            for (LogEvent probe : probes) {
                // extraDetails for a probe looks like "port=22"
                // We add the whole string -- each unique string is one distinct port
                distinctPorts.add(probe.extraDetails);
            }
            // Does this IP even meet the minimum number of distinct ports?
            if (distinctPorts.size() < PORT_SCAN_PORT_THRESHOLD) {
                continue;  // not enough distinct ports -- move on
            }
            // Find the earliest and latest timestamps
            LogEvent earliest = probes.get(0);
            LogEvent latest   = probes.get(0);

            for (LogEvent probe : probes) {
                if (probe.timestamp.isBefore(earliest.timestamp)) {
                    earliest = probe;
                }
                if (probe.timestamp.isAfter(latest.timestamp)) {
                    latest = probe;
                }
            }
            long minutesSpanned = Duration.between(earliest.timestamp, latest.timestamp).toMinutes();
            long secondsSpanned = Duration.between(earliest.timestamp, latest.timestamp).toSeconds();

            if (minutesSpanned <= PORT_SCAN_WINDOW_MINUTES) {
                String description = "Possible port scan from " + ipAddress
                        + ": " + distinctPorts.size() + " different ports probed" + " within " + secondsSpanned
                        + " seconds.";
                alerts.add(new Alert(latest.rawTimestamp, "MEDIUM", description));
            }
        }
        return alerts;
    }
}
