package java.siem;

/*
 * This class takes all the events and alerts we collected
 * and turns them into a single HTML file: our dashboard.
 */

import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;

public class DashboardBuilder {

    // Main method: build and save the full HTML dashboard
    public void buildDashboard(ArrayList<LogEvent> events, ArrayList<Alert> alerts,
                               String outputFileName) throws IOException {

        // Count events by type (for the bar chart)
        // e.g. {"AUTH_FAILED": 8, "AUTH_SUCCESS": 5, "PORT_SCAN_PROBE": 15}
        HashMap<String, Integer> eventCountsByType = new HashMap<>();

        for (LogEvent event : events) {
            if (!eventCountsByType.containsKey(event.eventType)) {
                eventCountsByType.put(event.eventType, 0);
            }
            eventCountsByType.put(event.eventType,
                    eventCountsByType.get(event.eventType) + 1);
        }
        // Count high-severity alerts (for the red summary card)
        int highSeverityCount = 0;

        for (Alert alert : alerts) {
            if (alert.severity.equals("HIGH")) {
                highSeverityCount++;
            }
        }
        // Build each section of the page separately
        // Breaking the HTML into small methods keeps things readable.
        String summaryCardsHtml = buildSummaryCards(events.size(), alerts.size(), highSeverityCount);
        String barChartHtml     = buildBarChart(eventCountsByType);
        String alertsTableHtml  = buildAlertsTable(alerts);
        String eventsTableHtml  = buildRecentEventsTable(events);

        // Assemble everything into one complete HTML page
        String fullPageHtml = buildFullPage(summaryCardsHtml, barChartHtml, alertsTableHtml, eventsTableHtml);

        // Write to file
        FileWriter writer = new FileWriter(outputFileName);
        writer.write(fullPageHtml);
        writer.close();

        System.out.println("  Dashboard saved to '" + outputFileName + "'.");
    }

    private String buildSummaryCards(int totalEvents, int totalAlerts, int highSeverityCount) {

    }

}
