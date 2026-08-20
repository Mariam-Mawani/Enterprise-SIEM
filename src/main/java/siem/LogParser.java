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
    public ArrayList<LogEvent> parseFile(String fileName) throws IOException {
        ArrayList<LogEvent> events = new ArrayList<>();

        // BufferedReader reads the file one line at a time, which is
        // memory-efficient (we don't load the whole file at once).
        BufferedReader reader = new BufferedReader(new FileReader(fileName));
        String rawLine;

        while ((rawLine = reader.readLine()) != null) {
            // Remove any leading/trailing whitespace
            String trimmedLine = rawLine.trim();
            // Skip completely blank lines
            if (trimmedLine.isEmpty()) {
                continue;
            }
        }
    }
}
