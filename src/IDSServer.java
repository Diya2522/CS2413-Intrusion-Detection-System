import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class IDSServer {

    public static void main(String[] args) {
        try {
            //Create the HTTP server on port 8080
            HttpServer server = HttpServer.create(new InetSocketAddress("0.0.0.0", 8080), 0);

            //Dashboard pages
            server.createContext("/", IDSServer::handlePage);

            //API routes that send the IDS results as JSON
            server.createContext("/api/alerts", IDSServer::handleAlerts);
            server.createContext("/api/summary", IDSServer::handleSummary);

            server.setExecutor(null);
            server.start();

            System.out.println("IDS Web Server started.");
            System.out.println("Open http://localhost:8080 in your browser");
            System.out.println("Press Ctrl+C to stop the server");

        } catch (IOException e) {
            System.err.println("Failed to start server: " + e.getMessage());
        }
    }

    //Sends the html, css and js files for the dashboard
    private static void handlePage(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();

        //Only these 3 files can be opened, anything else gives 404
        if (path.equals("/") || path.equals("/index.html")) {
            serveFile(exchange, "web/index.html", "text/html");
        } else if (path.equals("/style.css")) {
            serveFile(exchange, "web/style.css", "text/css");
        } else if (path.equals("/script.js")) {
            serveFile(exchange, "web/script.js", "application/javascript");
        } else {
            sendResponse(exchange, 404, "File Not Found", "text/plain");
        }
    }

    //Handles /api/alerts and sends the list of alerts
    private static void handleAlerts(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("GET")) {
            sendResponse(exchange, 405, "Method Not Allowed", "text/plain");
            return;
        }

        String filename = getDatasetFile(exchange);
        if (filename == null) {
            sendResponse(exchange, 400, "Invalid dataset", "text/plain");
            return;
        }

        try {
            //Run all three detectors on the dataset (already sorted by time)
            List<SecurityAlert> alerts = IDSAnalyzer.analyzeAll(filename);

            StringBuilder json = new StringBuilder("[");
            for (int i = 0; i < alerts.size(); i++) {
                SecurityAlert alert = alerts.get(i);

                if (i > 0) {
                    json.append(",");
                }

                json.append("{")
                    .append("\"timestamp\":\"").append(escapeJson(alert.getTimestamp().toString())).append("\",")
                    .append("\"severity\":\"").append(escapeJson(alert.getSeverity())).append("\",")
                    .append("\"attackType\":\"").append(escapeJson(alert.getAttackType())).append("\",")
                    .append("\"sourceIP\":\"").append(escapeJson(alert.getSourceIP())).append("\",")
                    .append("\"destinationIP\":\"").append(escapeJson(alert.getDestinationIP())).append("\",")
                    .append("\"description\":\"").append(escapeJson(alert.getDescription())).append("\"")
                    .append("}");
            }
            json.append("]");

            sendResponse(exchange, 200, json.toString(), "application/json");

        } catch (IOException | IllegalArgumentException e) {
            System.err.println(e.getMessage());
            sendResponse(exchange, 500, "Unable to analyze IDS data", "text/plain");
        }
    }

    //Handles /api/summary and sends the counts for the dashboard cards
    private static void handleSummary(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equals("GET")) {
            sendResponse(exchange, 405, "Method Not Allowed", "text/plain");
            return;
        }

        String filename = getDatasetFile(exchange);
        if (filename == null) {
            sendResponse(exchange, 400, "Invalid dataset", "text/plain");
            return;
        }

        try {
            List<NetworkEvent> events = TrafficReader.readEvents(filename);
            List<SecurityAlert> alerts = IDSAnalyzer.analyzeAll(filename);

            //Use SecurityReport to count alerts by severity and attack type
            SecurityReport report = new SecurityReport(events.size(), alerts);

            String json = "{"
                    + "\"totalEvents\":" + report.getTotalEvents() + ","
                    + "\"totalAlerts\":" + report.getTotalAlerts() + ","
                    + "\"high\":" + report.getSeverityCount("HIGH") + ","
                    + "\"medium\":" + report.getSeverityCount("MEDIUM") + ","
                    + "\"low\":" + report.getSeverityCount("LOW") + ","
                    + "\"bruteForce\":" + report.getAttackTypeCount("BRUTE_FORCE") + ","
                    + "\"portScan\":" + report.getAttackTypeCount("PORT_SCAN") + ","
                    + "\"highTraffic\":" + report.getAttackTypeCount("HIGH_TRAFFIC")
                    + "}";

            sendResponse(exchange, 200, json, "application/json");

        } catch (IOException | IllegalArgumentException e) {
            System.err.println(e.getMessage());
            sendResponse(exchange, 500, "Unable to generate IDS summary", "text/plain");
        }
    }

    //Reads a file from the web folder and sends it to the browser
    private static void serveFile(HttpExchange exchange, String filename, String contentType) throws IOException {
        if (!exchange.getRequestMethod().equals("GET")) {
            sendResponse(exchange, 405, "Method Not Allowed", "text/plain");
            return;
        }

        Path file = Path.of(filename);
        if (!Files.isRegularFile(file)) {
            sendResponse(exchange, 404, "File Not Found", "text/plain");
            return;
        }

        byte[] content = Files.readAllBytes(file);
        exchange.getResponseHeaders().set("Content-Type", contentType + "; charset=UTF-8");
        exchange.sendResponseHeaders(200, content.length);

        try (OutputStream output = exchange.getResponseBody()) {
            output.write(content);
        }
    }

    //Sends a text or JSON response with a status code
    private static void sendResponse(HttpExchange exchange, int status, String message, String contentType)
            throws IOException {
        byte[] content = message.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType + "; charset=UTF-8");
        exchange.sendResponseHeaders(status, content.length);

        try (OutputStream output = exchange.getResponseBody()) {
            output.write(content);
        }
    }

    //Makes text safe to put inside a JSON string
    private static String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    //Picks the CSV file from ?dataset=... in the URL
    //Only these 3 datasets are allowed so the user can't open other files
    private static String getDatasetFile(HttpExchange exchange) {
        String query = exchange.getRequestURI().getRawQuery();

        if (query == null) {
            return "data/realistic_events.csv";
        }
        if (query.equals("dataset=normal")) {
            return "data/normal_events.csv";
        }
        if (query.equals("dataset=malicious")) {
            return "data/network_events.csv";
        }
        if (query.equals("dataset=realistic")) {
            return "data/realistic_events.csv";
        }
        return null;
    }
}
