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

    // A table showing the most recent raw log events
    private String buildRecentEventsTable(ArrayList<LogEvent> events) {
        if (events.isEmpty()) {
            return "<p>No events found.</p>\n";
        }
        // Show the last 30 events, most recent first.
        // In a real SIEM you'd paginate thousands of events, but for
        // our demo dataset of ~28 events this shows everything.
        int startIndex = Math.max(0, events.size() - 30);
        StringBuilder rows = new StringBuilder();

        // Iterate backwards through the list so newest events appear at the top
        for (int i = events.size() - 1; i >= startIndex; i--) {
            LogEvent event = events.get(i);
            rows.append("<tr>\n");
            rows.append("  <td>").append(event.rawTimeStamp).append("</td>\n");
            rows.append("  <td>").append(event.eventType).append("</td>\n");
            rows.append("  <td>").append(event.ipAddress).append("</td>\n");
            rows.append("  <td>").append(event.extraDetails).append("</td>\n");
            rows.append("</tr>\n");
        }
        return "<table>\n"
                + "  <thead>"
                + "<tr><th>Time</th><th>Event Type</th><th>IP Address</th><th>Details</th></tr>"
                + "</thead>\n"
                + "  <tbody>\n" + rows + "  </tbody>\n"
                + "</table>\n";
    }

    // Assembles the full HTML page with CSS styles included
    private String buildFullPage(String summaryCards, String barChart, String alertsTable, String eventsTable) {

        // We use a StringBuilder here because we're joining many small
        // strings together. It's more efficient than many + operations.
        StringBuilder page = new StringBuilder();

        page.append("<!DOCTYPE html>\n");
        page.append("<html lang=\"en\">\n");
        page.append("<head>\n");
        page.append("  <meta charset=\"UTF-8\">\n");
        page.append("  <title>Mini SIEM Dashboard</title>\n");
        page.append("  <style>\n");

        // ---- CSS styles (dark theme) ----
        page.append("    body { font-family: Arial, Helvetica, sans-serif; background-color: #0f172a; color: #e2e8f0; margin: 0; padding: 30px; }\n");
        page.append("    h1 { color: #38bdf8; }\n");
        page.append("    h2 { border-bottom: 2px solid #334155; padding-bottom: 6px; margin-top: 40px; }\n");
        page.append("    p  { color: #94a3b8; }\n");
        page.append("    .summary-cards { display: flex; gap: 20px; margin: 20px 0; }\n");
        page.append("    .card { background-color: #1e293b; border-radius: 8px; padding: 20px 30px; text-align: center; flex: 1; }\n");
        page.append("    .card-danger { border: 1px solid #ef4444; }\n");
        page.append("    .card-number { font-size: 36px; font-weight: bold; color: #38bdf8; }\n");
        page.append("    .card-danger .card-number { color: #ef4444; }\n");
        page.append("    .card-label { margin-top: 6px; color: #94a3b8; }\n");
        page.append("    table { width: 100%; border-collapse: collapse; background-color: #1e293b; border-radius: 8px; overflow: hidden; margin-top: 10px; }\n");
        page.append("    th, td { text-align: left; padding: 10px 14px; border-bottom: 1px solid #334155; font-size: 14px; }\n");
        page.append("    th { background-color: #334155; color: #f1f5f9; }\n");
        page.append("    .badge { padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; }\n");
        page.append("    .severity-high   { background-color: #ef4444; color: white; }\n");
        page.append("    .severity-medium { background-color: #f59e0b; color: white; }\n");
        page.append("    .bar-row   { display: flex; align-items: center; margin: 10px 0; }\n");
        page.append("    .bar-label { width: 160px; font-size: 14px; color: #cbd5e1; }\n");
        page.append("    .bar-track { flex: 1; background-color: #1e293b; border-radius: 4px; height: 18px; margin-right: 12px; }\n");
        page.append("    .bar-fill  { height: 100%; background-color: #38bdf8; border-radius: 4px; }\n");
        page.append("    .bar-count { width: 40px; text-align: right; color: #94a3b8; }\n");

        page.append("  </style>\n");
        page.append("</head>\n");
        page.append("<body>\n");

        page.append("  <h1>Mini SIEM Dashboard</h1>\n");
        page.append("  <p>A simple Security Information and Event Management report, built in Java.</p>\n");

        page.append(summaryCards);

        page.append("  <h2>Events by Type</h2>\n");
        page.append(barChart);

        page.append("  <h2>Alerts</h2>\n");
        page.append(alertsTable);

        page.append("  <h2>Recent Events</h2>\n");
        page.append(eventsTable);

        page.append("</body>\n");
        page.append("</html>\n");

        return page.toString();
    }
}
