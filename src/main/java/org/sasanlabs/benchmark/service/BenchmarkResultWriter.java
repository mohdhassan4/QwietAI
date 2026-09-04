package org.sasanlabs.benchmark.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;
import org.sasanlabs.benchmark.model.BenchmarkResult;
import org.sasanlabs.internal.utility.SafePathUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Persists a {@link BenchmarkResult} to a JSON file under the configured benchmarks directory.
 * Filename is derived from the (sanitised) tool name; existing files are overwritten so callers
 * always see the latest run for a given tool.
 */
@Component
public class BenchmarkResultWriter {

    private final ObjectMapper objectMapper;
    private final String defaultBenchmarksDir;

    public BenchmarkResultWriter(
            ObjectMapper objectMapper,
            @Value("${benchmark.output.dir:benchmarks}") String defaultBenchmarksDir) {
        this.objectMapper = objectMapper;
        this.defaultBenchmarksDir = defaultBenchmarksDir;
    }

    public Path write(BenchmarkResult result) throws IOException {
        return write(result, defaultBenchmarksDir);
    }

    public Path write(BenchmarkResult result, String benchmarksDir) throws IOException {
        Path dir = safeBenchmarksDir(benchmarksDir);
        Files.createDirectories(dir);
        String fileName = sanitizeToolName(result.getTool()) + "-results.json";
        Path target = safeTargetWithin(dir, fileName);
        Path temp = Files.createTempFile(dir, fileName + ".", ".tmp");
        try {
            objectMapper.writerWithDefaultPrettyPrinter().writeValue(temp.toFile(), result);
            moveAtomicallyOrReplace(temp, target);
        } catch (IOException ioe) {
            Files.deleteIfExists(temp);
            throw ioe;
        }
        return target;
    }

    /**
     * Canonicalises the configured output directory and refuses {@code ".."} segments (CWE-22).
     *
     * <p>Surfaced as an {@link IOException} so callers keep their existing persistence handling.
     */
    private static Path safeBenchmarksDir(String benchmarksDir) throws IOException {
        try {
            return SafePathUtils.canonicalizeConfiguredPath(benchmarksDir);
        } catch (IllegalArgumentException unsafe) {
            throw new IOException(
                    "Refusing to write benchmark results outside the configured directory: "
                            + unsafe.getMessage(),
                    unsafe);
        }
    }

    /** Keeps the report file inside the benchmarks directory it was resolved against. */
    private static Path safeTargetWithin(Path dir, String fileName) throws IOException {
        try {
            return SafePathUtils.requireWithin(dir, dir.resolve(fileName));
        } catch (IllegalArgumentException unsafe) {
            throw new IOException(
                    "Refusing to write the benchmark report: " + unsafe.getMessage(), unsafe);
        }
    }

    private static void moveAtomicallyOrReplace(Path source, Path target) throws IOException {
        try {
            Files.move(
                    source,
                    target,
                    StandardCopyOption.ATOMIC_MOVE,
                    StandardCopyOption.REPLACE_EXISTING);
        } catch (AtomicMoveNotSupportedException notSupported) {
            Files.move(source, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static final int MAX_TOOL_LENGTH = 64;

    static String sanitizeToolName(String tool) {
        if (tool == null) {
            return "unknown";
        }
        String lowered = tool.trim().toLowerCase(Locale.ROOT);
        String cleaned = lowered.replaceAll("[^a-z0-9_-]", "");
        if (cleaned.isEmpty()) {
            return "unknown";
        }
        if (cleaned.length() > MAX_TOOL_LENGTH) {
            cleaned = cleaned.substring(0, MAX_TOOL_LENGTH);
        }
        return cleaned;
    }
}
