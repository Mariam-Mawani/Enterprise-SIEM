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
        System.out.println("  Adding normal login events...");


        String[][] normalLogins = {
                {"mariam", "10.0.0.5"},
                {"thabo", "10.0.0.8"},
                {"Adam", "10.0.0.12"}
        };

        for (int i = 0; i < normalLogins.length; i++) {
            String username = normalLogins[i][0];
            String ipAddress = normalLogins[i][1];

            logLines.add(buildLogLine(currentTime, "AUTH_SUCCESS", ipAddress, "user=" + username));
            currentTime = currentTime.plusMinutes(7);
        }

        logLines.add(buildLogLine(currentTime, "AUTH_FAILED",  "10.0.0.8", "user=thabo"));
        currentTime = currentTime.plusSeconds(20);
        logLines.add(buildLogLine(currentTime, "AUTH_SUCCESS", "10.0.0.8", "user=thabo"));
        currentTime = currentTime.plusMinutes(10);


    }
}
