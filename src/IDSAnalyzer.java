import java.io.IOException;
import java.util.List;
import java.util.ArrayList;

public class IDSAnalyzer{
    public static List<SecurityAlert> analyzeAll(String fileName) throws IOException{
        IDSConfig config = new IDSConfig("config/ids.properties");
        List<SecurityAlert> alertList = new ArrayList<>();

        //Read Network Events from CSV
        List<NetworkEvent> eventList = TrafficReader.readEvents(fileName);
        
        //Detect Brute Force, Traffic Volume, and Port Scan attacks and add them to the alert list
        alertList.addAll(BruteForceDetector.detect(eventList, config));
        alertList.addAll(TrafficVolumeDetector.detect(eventList, config));
        alertList.addAll(PortScanDetector.detect(eventList, config));

        //Sort the alerts by timestamp
        alertList.sort((a, b) -> a.getTimestamp().compareTo(b.getTimestamp())); 
        
        //Return the list of alerts
        return alertList;
    }
    
    public static List<SecurityAlert> analyzeBF(String fileName) throws IOException{
        IDSConfig config = new IDSConfig("config/ids.properties");
        //Read Network Events from CSV
        List<NetworkEvent> eventList = TrafficReader.readEvents(fileName);
        
        //Detect Brute Force attacks and add them to the alert list
        List<SecurityAlert> alertList = new ArrayList<>();
        alertList.addAll(BruteForceDetector.detect(eventList, config));

        //Sort the alerts by timestamp
        alertList.sort((a, b) -> a.getTimestamp().compareTo(b.getTimestamp())); 
        
        //Return the list of alerts
        return alertList;
    }

    public static List<SecurityAlert> analyzeTV(String fileName) throws IOException{
        IDSConfig config = new IDSConfig("config/ids.properties");
        //Read Network Events from CSV
        List<NetworkEvent> eventList = TrafficReader.readEvents(fileName);
        
        //Detect Traffic Volume attacks and add them to the alert list
        List<SecurityAlert> alertList = new ArrayList<>();
        alertList.addAll(TrafficVolumeDetector.detect(eventList, config));

        //Sort the alerts by timestamp
        alertList.sort((a, b) -> a.getTimestamp().compareTo(b.getTimestamp())); 
        
        //Return the list of alerts
        return alertList;
    }

    public static List<SecurityAlert> analyzePS(String fileName) throws IOException{
        IDSConfig config = new IDSConfig("config/ids.properties");
        //Read Network Events from CSV
        List<NetworkEvent> eventList = TrafficReader.readEvents(fileName);
        
        //Detect Port Scan attacks and add them to the alert list
        List<SecurityAlert> alertList = new ArrayList<>();
        alertList.addAll(PortScanDetector.detect(eventList, config));

        //Sort the alerts by timestamp
        alertList.sort((a, b) -> a.getTimestamp().compareTo(b.getTimestamp())); 
        
        //Return the list of alerts
        return alertList;
    }
}