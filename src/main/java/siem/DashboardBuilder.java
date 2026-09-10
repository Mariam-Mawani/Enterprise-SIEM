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

    // The three number cards at the top of the page
    private String buildSummaryCards(int totalEvents, int totalAlerts, int highSeverityCount) {

        return "<div class=\"summary-cards\">\n"
                + " <div class=\"card\">\n"
                + "    <div class=\"card-number\">" + totalEvents + "</div>\n"
                + "    <div class=\"card-label\">Total Events</div>\n"
                + "  </div>\n"
                + "  <div class=\"card\">\n"
                + "    <div class=\"card-number\">" + totalAlerts + "</div>\n"
                + "    <div class=\"card-label\">Total Alerts</div>\n"
                + "  </div>\n"
                + "  <div class=\"card card-danger\">\n"
                + "    <div class=\"card-number\">" + highSeverityCount + "</div>\n"
                + "    <div class=\"card-label\">High Severity</div>\n"
                + "  </div>\n"
                + "</div>\n";
    }

    // A simple CSS bar chart (no JavaScript library needed)
    // Each bar is just a <div> whose width is a percentage.
    private String buildBarChart(HashMap<String, Integer> eventCountsByType) {

        if (eventCountsByType.isEmpty()) {
            return "<p>No events to display.</p>\n";
        }
        // Find the highest count so we can scale bar widths correctly
        int largestCount = 0;

        for (int count : eventCountsByType.values()) {
            if (count > largestCount) {
                largestCount = count;
            }
        }
        StringBuilder html = new StringBuilder();

        for (String eventType : eventCountsByType.keySet()) {
            int count = eventCountsByType.get(eventType);
            // Width as a percentage of the widest bar
            int barWidthPercent = (count * 100) / largestCount;

            html.append("<div class=\"bar-row\">\n");
            html.append("  <div class=\"bar-label\">").append(eventType).append("</div>\n");
            html.append("  <div class=\"bar-track\">");
            html.append("<div class=\"bar-fill\" style=\"width: ").append(barWidthPercent).append("%;\"></div>");
            html.append("</div>\n");
            html.append("  <div class=\"bar-count\">").append(count).append("</div>\n");
            html.append("</div>\n");
        }
        return html.toString();
    }

    // A table showing every alert with a severity colour badge
    private String buildAlertsTable(ArrayList<Alert> alerts) {
        if (alerts.isEmpty()) {
            return "<p>No alerts were raised. Everything looks normal.</p>\n";
        }

        StringBuilder rows = new StringBuilder();

        for (Alert alert : alerts) {
            // Pick a CSS class for the badge colour
            String badgeClass = alert.severity.equals("HIGH") ? "severity-high" : "severity-medium";

            rows.append("<tr>\n");
            rows.append("  <td>").append(alert.timestamp).append("</td>\n");
            rows.append("  <td><span class=\"badge ").append(badgeClass).append("\">")
                    .append(alert.severity).append("</span></td>\n");
            rows.append("  <td>").append(alert.description).append("</td>\n");
            rows.append("</tr>\n");
        }

        return "<table>\n"
                + "  <thead><tr><th>Time</th><th>Severity</th><th>Description</th></tr></thead>\n"
                + "  <tbody>\n" + rows + "  </tbody>\n"
                + "</table>\n";
    }

}
