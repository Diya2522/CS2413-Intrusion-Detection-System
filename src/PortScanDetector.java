import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PortScanDetector {
    public static List<SecurityAlert> detect(List<NetworkEvent> events, IDSConfig config) {
        int threshold = config.getPositiveInt("portscan.threshold");
        int windowSeconds = config.getPositiveInt("portscan.windowSeconds");
        List<SecurityAlert> alerts = new ArrayList<>();
        Map<List<String>, Map<Integer, Instant>> portsByAddress = new HashMap<>();

        List<NetworkEvent> sortedEvents = new ArrayList<>(events);
        sortedEvents.sort(Comparator.comparing(NetworkEvent::getTimestamp));

        for (NetworkEvent event : sortedEvents) {
            if (!"CONNECTION".equals(event.getEventType())) {
                continue;
            }

            List<String> addresses = List.of(event.getSourceIP(), event.getDestinationIP());
            Map<Integer, Instant> recentPorts = portsByAddress.computeIfAbsent(
                    addresses, key -> new HashMap<>());

            Instant timestamp = event.getTimestamp();
            Instant windowStart = timestamp.minusSeconds(windowSeconds);
            recentPorts.values().removeIf(lastSeen -> lastSeen.isBefore(windowStart));

            // Each port counts once, even if there were several connections to it.
            int previousCount = recentPorts.size();
            recentPorts.put(event.getDestinationPort(), timestamp);

            if (previousCount < threshold && recentPorts.size() == threshold) {
                String description = threshold + " unique destination ports within "
                        + windowSeconds + " seconds";
                alerts.add(new SecurityAlert(timestamp, "MEDIUM", "PORT_SCAN",
                        event.getSourceIP(), event.getDestinationIP(), description));
            }
        }

        return alerts;
    }
}