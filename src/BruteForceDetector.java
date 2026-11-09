import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class BruteForceDetector {
    public static List<SecurityAlert> detect(List<NetworkEvent> events, IDSConfig config) {
        int threshold = config.getPositiveInt("bruteforce.threshold");
        int windowSeconds = config.getPositiveInt("bruteforce.windowSeconds");
        List<SecurityAlert> alerts = new ArrayList<>();
        Map<List<String>, Deque<Instant>> failuresByAddress = new HashMap<>();

        List<NetworkEvent> sortedEvents = new ArrayList<>(events);
        sortedEvents.sort(Comparator.comparing(NetworkEvent::getTimestamp));

        for (NetworkEvent event : sortedEvents) {
            if (!"LOGIN_FAIL".equals(event.getEventType())) {
                continue;
            }

            List<String> addresses = List.of(event.getSourceIP(), event.getDestinationIP());
            Deque<Instant> failures = failuresByAddress.computeIfAbsent(
                    addresses, key -> new ArrayDeque<>());

            Instant timestamp = event.getTimestamp();
            Instant windowStart = timestamp.minusSeconds(windowSeconds);
            while (!failures.isEmpty() && failures.peekFirst().isBefore(windowStart)) {
                failures.removeFirst();
            }
            failures.addLast(timestamp);

            // Alert when the count first reaches the threshold for this burst.
            if (failures.size() == threshold) {
                String description = threshold + " failed login attempts within "
                        + windowSeconds + " seconds";
                alerts.add(new SecurityAlert(timestamp, "HIGH", "BRUTE_FORCE",
                        event.getSourceIP(), event.getDestinationIP(), description));
            }
        }

        return alerts;
    }
}