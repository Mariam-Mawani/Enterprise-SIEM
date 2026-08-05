package java.siem;

import java.io.IOException;
import java.time.LocalDate;
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


    }
}
