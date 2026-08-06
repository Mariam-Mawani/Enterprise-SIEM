package main.java.siem;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;

public class SampleLogGenerator {

    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    public void generate(String outputFileName) throws IOException{
        ArrayList<String> logLines = new ArrayList<>();
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

        logLines.add(buildLogLine(currentTime, "AUTH_FAILED",  "10.0.0.8", "user=thabo"));
        currentTime = currentTime.plusSeconds(20);
        logLines.add(buildLogLine(currentTime, "AUTH_SUCCESS", "10.0.0.8", "user=thabo"));
        currentTime = currentTime.plusMinutes(10);


        // Brute-force attack
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
