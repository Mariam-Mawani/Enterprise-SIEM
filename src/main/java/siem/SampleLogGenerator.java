package main.java.siem;

import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;

public class SampleLogGenerator {

    // The date/time format we use throughout the entire project. Using a constant
    // means if we ever change the format, we only need to change it in one place.
    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // This is the main method of this class. Call it to create the log file.
    public void generate(String outputFileName) throws IOException{
        // Collect all lines into this list, then write them all to the file
        // at the end
        ArrayList<String> logLines = new ArrayList<>();
        // Start all events at 3:00 AM on a specific date. We keep adding to
        // currentTime variable as we go, so each event, is a bit later than the one before
        LocalDateTime currentTime = LocalDateTime.of(2023, 6, 28, 3, 0, 0);

        // Normal logins
        System.out.println("  Adding normal login events...");

        // 3 real employees arriving and logging in normally
        String[][] normalLogins = {
                {"mariam", "10.0.0.5"},
                {"thabo", "10.0.0.8"},
                {"Adam", "10.0.0.12"}
        };

        for (int i = 0; i < normalLogins.length; i++) {
            String username = normalLogins[i][0];
            String ipAddress = normalLogins[i][1];

            logLines.add(buildLogLine(currentTime, "AUTH_SUCCESS", ipAddress, "user=" + username));
            currentTime = currentTime.plusMinutes(7);   // next login 7 minutes later
        }

        // One realistic "oops, I mistyped my password" moment.
        // ONE failed login followed by a success is completely normal.
        // It should NOT trigger our brute-force alert.
        logLines.add(buildLogLine(currentTime, "AUTH_FAILED",  "10.0.0.8", "user=thabo"));
        currentTime = currentTime.plusSeconds(20);
        logLines.add(buildLogLine(currentTime, "AUTH_SUCCESS", "10.0.0.8", "user=thabo"));

        // Leave a 10-minute quiet gap before the attack starts
        currentTime = currentTime.plusMinutes(10);


        // Brute-force attack
        // An attacker rapidly guessing passwords for "admin".
        // 8 failed logins from the same IP in under 2 minutes
        // is a classic brute-force signature.
        System.out.println("  Adding brute-force attack events...");

        String attackerIp = "198.51.100.23";
        int numberOfGuesses = 8;

        for (int attempt = 0; attempt < numberOfGuesses; attempt++) {
            logLines.add(buildLogLine(currentTime,"AUTH_FAILED", attackerIp, "user=admin"));
            currentTime = currentTime.plusSeconds(15);  // One guess every 15 seconds
        }
        // Leave 15 minute gap before the prot scan
        currentTime = currentTime.plusMinutes(15);



        // Port scan
        // An attacker probing many different ports rapidly,
        // looking for open/vulnerable services.
        System.out.println("  Adding port scan events...");

        String scannerIp = "203.0.113.45";
        int[] portsToScan = {21, 22, 23, 25, 53, 80, 110, 139, 143,
                443, 445, 993, 995, 3306, 3389};

        for (int port : portsToScan) {
            logLines.add(buildLogLine(currentTime,"PORT_SCAN_PROBE", scannerIp, "port=" + port));
            currentTime = currentTime.plusSeconds(2);   // One probe every 2 seconds
        }

        // Write every line to the log file
        FileWriter fileWriter = new FileWriter(outputFileName);
        for (String line : logLines) {
            fileWriter.write(line + "\n");
        }
        fileWriter.close();

        System.out.println("  Wrote " + logLines.size() + " log lines to '"
                + outputFileName + "'.");
    }

    // Helper method. builds log line in our standard format
    private String buildLogLine(LocalDateTime time, String eventType, String ipAddress, String details) {
        // Format. "2026-06-28 03:31:20 | AUTH_FAILED | ip=198.51.100.23 | user=admin"
        return time.format(TIMESTAMP_FORMAT)
                + " | " + eventType
                + " | ip= " + ipAddress
                + " | " + details;
    }
}
