import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

public class TrafficVolumeDetector {
    public static List<SecurityAlert> detect(List<NetworkEvent> events, IDSConfig config) {
        long threshold = config.getPositiveLong("traffic.bytesThreshold");
        List<SecurityAlert> alerts = new ArrayList<>();

        for (NetworkEvent event : events) {
            if (event.getBytes() >= threshold) {
                String description = "Traffic event containing " + event.getBytes() + " bytes";
                alerts.add(new SecurityAlert(event.getTimestamp(), "HIGH", "HIGH_TRAFFIC",
                        event.getSourceIP(), event.getDestinationIP(), description));
            }
        }

        alerts.sort(Comparator.comparing(SecurityAlert::getTimestamp));
        return alerts;
    }
}