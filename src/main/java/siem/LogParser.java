package java.siem;

/*  * This class reads the raw log file (a plain text file) and
 * converts each line into a LogEvent object that the rest of
 * our program can work with easily.
 */

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;


// The same timestamp format used by SampleLogGenerator --
// both classes must agree on this or parsing will fail.
public class LogParser {

    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    // Read every line in the file and return a list of events
    public ArrayList<LogEvent> parseFile(String filename) throws IOException {
        ArrayList<LogEvent> events = new ArrayList<>();

        // BufferedReader reads the file one line at a time, which is
        // memory-efficient (we don't load the whole file at once).
        BufferedReader reader = new BufferedReader(new FileReader(filename));
        String rawLine;

        while ((rawLine = reader.readLine()) != null) {
            // Remove any leading/trailing whitespace
            String trimmedLine = rawLine.trim();
            // Skip completely blank lines
            if (trimmedLine.isEmpty()) {
                continue;
            }
            // Try to parse this line into a logEvent object
            LogEvent event = parseSingleLine(trimmedLine);
            // parseSingleLine returns null if a line is malformed.
            // We skip those lines rather than crashing.
            if(event != null) {
                events.add(event);
            }
        }
        reader.close();
        return events;
    }

    // Parse ONE line of text into a LogEvent object
    private LogEvent parseSingleLine(String rawLine){
        String[] sections = rawLine.split(" \\| ");

        // We need at least 3 sections: timestamp, event type, ip field.
        // If a line doesn't have at least 3, it's malformed -- skip it.
        if (sections.length < 3) {
            System.out.println("Warning: skipping malformed line: " + rawLine);
            return null;
        }

        // Pull out the timestamp and event type (always in the same place)
        String rawTimestamp = sections[0];
        String eventType    = sections[1];

        // Parse the remaining sections as key=value pairs
        // "ip=198.51.100.23" or "user=admin" or "port=22"
        String ipAddress    = "unknown";
        String extraDetails = "";

        for (int i = 2; i < sections.length; i++) {
            String section = sections[i];
            // Skip any section that doesn't contain "=" (not a key=value pair)
            if (!section.contains("=")) {
                continue;
            }


        }
    }
}
