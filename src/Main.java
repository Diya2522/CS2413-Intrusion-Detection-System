import java.util.ArrayList;
import java.util.List;
import java.io.IOException;

public class Main {

public static void main(String[] args){
    try {
        String fileName = "data/network_events.csv";
        List<SecurityAlert> alertsBF = new ArrayList<>();
        List<SecurityAlert> alertsPS = new ArrayList<>();
        List<SecurityAlert> alertsTV = new ArrayList<>();
        List<SecurityAlert> allAlerts = new ArrayList<>();

        
        if(args.length > 0) {
            fileName = args[0];
        }
        else{
            System.out.println("No input file provided. Using default: " + fileName);
        }
        
        List<NetworkEvent> eventList = TrafficReader.readEvents(fileName);
        System.out.println("\nNetwork Traffic Analysis");
        System.out.println("\nTotal Events Analyzed: " + eventList.size());
        
        if(eventList.isEmpty()) {
            System.out.println("No events to analyze.");
            return;
        }
        for (NetworkEvent event : eventList) {
            String output = event.toString();
            System.out.println(output);
        }


        alertsBF = IDSAnalyzer.analyzeBF(fileName);
        alertsPS = IDSAnalyzer.analyzePS(fileName);
        alertsTV = IDSAnalyzer.analyzeTV(fileName);
        allAlerts = IDSAnalyzer.analyzeAll(fileName);
        System.out.println("\n-----Security Alerts-----\n");

        System.out.println("\n-----Brute Force Alerts-----");
        if (alertsBF.isEmpty()) {
            System.out.println("No Brute Force alerts detected.");
        }
        for (SecurityAlert alert : alertsBF) {
            String output = alert.toString();
            System.out.println(output);
        }

        System.out.println("\n-----Port Scan Alerts-----");
        if (alertsPS.isEmpty()) {
            System.out.println("No Port Scan alerts detected.");
        }
        for (SecurityAlert alert : alertsPS) {
            String output = alert.toString();
            System.out.println(output);
        }

        System.out.println("\n-----Traffic Violation Alerts-----");
        if (alertsTV.isEmpty()) {
            System.out.println("No Traffic Violation alerts detected.");
        }
        for (SecurityAlert alert : alertsTV) {
            String output = alert.toString();
            System.out.println(output);
        }

        AlertLogger.saveAlerts(allAlerts, "output/security_alerts.csv");
        System.out.println("\n" + allAlerts.size() + " alerts have been saved to output/security_alerts.csv");

        SecurityReport report = new SecurityReport(eventList.size(), allAlerts);
        System.out.println("\n" + report.toString());

    } catch (IOException e) {
        System.err.println("Error reading configuration or network events: " + e.getMessage());
    } catch (IllegalArgumentException e) {
        System.err.println("Configuration error: " + e.getMessage());
    }
}}
