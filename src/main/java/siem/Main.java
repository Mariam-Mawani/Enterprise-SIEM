package java.siem;

/* This is the entry point for our Mini SIEM.
 *
 * It calls each of the other classes in order, passing data
 * from one step to the next -- like an assembly line:
 *   Step 1: Generate a sample log file to analyse
 *   Step 2: Parse the log file into LogEvent objects
 *   Step 3: Run the detection rules, get a list of Alerts
 *   Step 4: Print a summary table to the console
 *   Step 5: Build an HTML dashboard and save it to disk
 */

import java.util.ArrayList;

public class Main {

    private static final String LOG_FILE = "sample_auth.log";
    private static final String DASHBOARD_FILE = "dashboard.html";

    public static void main(String[] args) {

        // We wrap everything in try/catch so that if anything goes
        // wrong (e.g. a file can't be written), we get a clear error
        // message instead of a crash with no explanation.
        try {
            System.out.println("=".repeat(60));
            System.out.println("  MINI SIEM - Starting up");
            System.out.println("=".repeat(60));

            // STEP 1: Generate a synthetic log file to analyse
            System.out.println("\n[Step 1] Generating sample log file...");
            SampleLogGenerator generator = new SampleLogGenerator();
            generator.generate(LOG_FILE);

            // STEP 2: Parse the log file into LogEvent objects
            System.out.println("\n[Step 2] Parsing log file...");
            LogParser parser = new LogParser();
            ArrayList<LogEvent> events = parser.parseFile(LOG_FILE);
            System.out.println("  Parsed " + events.size() + " events successfully.");

            // STEP 3: Run all detection rules
            System.out.println("\n[step 3] Running detection rules...");
            DetectionEngine engine = new DetectionEngine();
            ArrayList<Alert> alerts = engine.runAllRules(events);

            // STEP 4: Print a summary to the console
            System.out.println("\n[Step 4] Detection summary: ");
            printSummary(events, alerts);

            // STEP 5: Build and save the HTML dashboard
            System.out.println("\n[Step] Building HTML dashboard...");
            DashboardBuilder dashboardBuilder = new DashboardBuilder();
            dashboardBuilder.buildDashboard(events, alerts, DASHBOARD_FILE);

            System.out.println("\n" + "=".repeat(60));
            System.out.println("  Done! Open '" + DASHBOARD_FILE + "' in your browser.");
            System.out.println("=".repeat(60));


        } catch (Exception error) {
            System.out.println("\nSomething went wrong: " + error.getMessage());
            error.printStackTrace();
        }
    }

    // Print a nicely formatted summary table to the console
    private static void printSummary(ArrayList<LogEvent> events, ArrayList<Alert> alerts) {

        System.out.println("-".repeat(60));
        System.out.println("  Total log events processed : " + events.size());
        System.out.println("  Total alerts raised        : " + alerts.size());
        System.out.println("-".repeat(60));

        if (alerts.isEmpty()) {
            System.out.println("  No suspicious activity detected.");
        }
        else {
            for (Alert alert : alerts) {
                System.out.println(" " + alert.toString());
            }
        }
        System.out.println("-".repeat(60));
        System.out.println();
    }
}
