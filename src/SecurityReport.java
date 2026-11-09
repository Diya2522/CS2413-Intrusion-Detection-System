import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SecurityReport {
    private final int totalEvents;
    private final int totalAlerts;
    private final Map<String, Integer> severityCounts = new HashMap<>();
    private final Map<String, Integer> attackTypeCounts = new HashMap<>();

    public SecurityReport(int totalEvents, List<SecurityAlert> alerts) {
        this.totalEvents = totalEvents;
        this.totalAlerts = alerts.size();

        for (SecurityAlert alert : alerts) {
            String severity = alert.getSeverity();
            severityCounts.put(severity, severityCounts.getOrDefault(severity, 0) + 1);

            String attackType = alert.getAttackType();
            attackTypeCounts.put(attackType, attackTypeCounts.getOrDefault(attackType, 0) + 1);
        }
    }

    public int getTotalEvents() {
        return totalEvents;
    }

    public int getTotalAlerts() {
        return totalAlerts;
    }

    public int getSeverityCount(String severity) {
        return severityCounts.getOrDefault(severity, 0);
    }

    public int getAttackTypeCount(String attackType) {
        return attackTypeCounts.getOrDefault(attackType, 0);
    }

    @Override
    public String toString() {
        return """
                ========== IDS SECURITY SUMMARY ==========

                Total Network Events: %d
                Total Security Alerts: %d

                Alerts by Severity:
                HIGH:     %d
                MEDIUM:   %d
                LOW:      %d
                CRITICAL: %d

                Alerts by Attack Type:
                BRUTE_FORCE:  %d
                PORT_SCAN:    %d
                HIGH_TRAFFIC: %d

                ==========================================""".formatted(
                totalEvents, totalAlerts,
                getSeverityCount("HIGH"), getSeverityCount("MEDIUM"),
                getSeverityCount("LOW"), getSeverityCount("CRITICAL"),
                getAttackTypeCount("BRUTE_FORCE"), getAttackTypeCount("PORT_SCAN"),
                getAttackTypeCount("HIGH_TRAFFIC"));
    }
}