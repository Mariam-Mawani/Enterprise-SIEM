package java.siem;

/*  * This class reads the raw log file (a plain text file) and
 * converts each line into a LogEvent object that the rest of
 * our program can work with easily.
 */

import java.time.format.DateTimeFormatter;


// The same timestamp format used by SampleLogGenerator --
// both classes must agree on this or parsing will fail.
public class LogParser {
    private static final DateTimeFormatter TIMESTAMP_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
}
