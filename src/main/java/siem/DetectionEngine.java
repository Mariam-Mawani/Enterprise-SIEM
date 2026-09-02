package java.siem;

/*
 * This class contains our "detection rules" -- the logic that
 * looks across all the log events and spots suspicious patterns.
 */



public class DetectionEngine {

    // Rule thresholds -- change these numbers to make the rules more or less sensitive
    // (this is called "tuning" in real SIEM deployments).

    // Brute-force rule
    private static final int BRUTE_FORCE_LOGIN_THRESHOLD = 5;   // Number of failures
    private static final long BRUTE_FORCE_WINDOW_MINUTES = 5;   // Within this time window
    // Port scan rule
    private static final int PORT_SCAN_PORT_THRESHOLD = 10;     // Number of distinct ports
    private static final long PORT_SCAN_WINDOW_MINUTES = 1;     // Within this time window





}
