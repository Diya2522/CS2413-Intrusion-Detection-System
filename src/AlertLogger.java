import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.List;

public class AlertLogger {
    public static void saveAlerts(List<SecurityAlert> alerts, String filename) throws IOException {
        Path target = Path.of(filename).toAbsolutePath();
        Path directory = target.getParent();
        Files.createDirectories(directory);
        Path tempFile = Files.createTempFile(directory, "alerts-", ".tmp");

        try {
            try (BufferedWriter writer = Files.newBufferedWriter(tempFile)) {
                writer.write("timestamp,severity,attackType,sourceIP,destinationIP,description");
                writer.newLine();

                for (SecurityAlert alert : alerts) {
                    writer.write(String.join(",",
                            alert.getTimestamp().toString(),
                            csvField(alert.getSeverity()),
                            csvField(alert.getAttackType()),
                            csvField(alert.getSourceIP()),
                            csvField(alert.getDestinationIP()),
                            csvField(alert.getDescription())));
                    writer.newLine();
                }
            }

            // Replace the previous log only after the new CSV has been written.
            Files.move(tempFile, target, StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } finally {
            Files.deleteIfExists(tempFile);
        }
    }

    private static String csvField(String value) {
        if (value.contains(",") || value.contains("\"")
                || value.contains("\n") || value.contains("\r")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }
}