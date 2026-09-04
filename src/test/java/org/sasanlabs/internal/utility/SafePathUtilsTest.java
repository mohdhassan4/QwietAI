package org.sasanlabs.internal.utility;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Containment checks behind the path traversal (CWE-22) remediations. */
class SafePathUtilsTest {

    @Test
    void resolveChildWithin_returnsTheRequestedFileInsideTheBaseDirectory(@TempDir Path tempDir)
            throws Exception {
        Path base = Files.createDirectories(tempDir.resolve("base"));
        Path file = Files.createFile(base.resolve("report.json"));

        Path resolved = SafePathUtils.resolveChildWithin(base, "report.json");

        assertThat(resolved).isEqualTo(file.toRealPath());
    }

    @Test
    void resolveChildWithin_rejectsNamesThatAreNotPlainFileNames(@TempDir Path tempDir) {
        assertRejected(() -> SafePathUtils.resolveChildWithin(tempDir, ".."));
        assertRejected(() -> SafePathUtils.resolveChildWithin(tempDir, "."));
        assertRejected(() -> SafePathUtils.resolveChildWithin(tempDir, "sub/report.json"));
        assertRejected(() -> SafePathUtils.resolveChildWithin(tempDir, "/etc/passwd"));
        assertRejected(() -> SafePathUtils.resolveChildWithin(tempDir, "  "));
        assertRejected(() -> SafePathUtils.resolveChildWithin(tempDir, null));
        assertRejected(() -> SafePathUtils.resolveChildWithin(null, "report.json"));
        assertRejected(() -> SafePathUtils.resolveChildWithin(tempDir, "a" + ((char) 0) + "b"));
    }

    /** A link inside the base directory must not become a way out of it. */
    @Test
    void resolveChildWithin_rejectsASymlinkPointingOutOfTheBaseDirectory(@TempDir Path tempDir)
            throws Exception {
        Path base = Files.createDirectories(tempDir.resolve("base"));
        Path outside = Files.createFile(tempDir.resolve("outside.txt"));
        try {
            Files.createSymbolicLink(base.resolve("link.txt"), outside);
        } catch (IOException | UnsupportedOperationException unsupported) {
            assumeTrue(false, "symlinks are not supported here");
        }

        assertRejected(() -> SafePathUtils.resolveChildWithin(base, "link.txt"));
    }

    @Test
    void resolveChildWithin_missingFileThrowsIOException(@TempDir Path tempDir) {
        assertThatThrownBy(() -> SafePathUtils.resolveChildWithin(tempDir, "absent.json"))
                .isInstanceOf(IOException.class);
    }

    @Test
    void canonicalizeConfiguredPath_makesRelativePathsAbsolute() {
        Path resolved = SafePathUtils.canonicalizeConfiguredPath("benchmarks");

        assertThat(resolved).isAbsolute();
        assertThat(resolved).isEqualTo(Paths.get("benchmarks").toAbsolutePath().normalize());
    }

    @Test
    void canonicalizeConfiguredPath_keepsAbsolutePaths(@TempDir Path tempDir) {
        Path resolved = SafePathUtils.canonicalizeConfiguredPath(tempDir.toString());

        assertThat(resolved).isEqualTo(tempDir.toAbsolutePath().normalize());
    }

    @Test
    void canonicalizeConfiguredPath_rejectsParentSegmentsAndBlanks() {
        assertRejected(() -> SafePathUtils.canonicalizeConfiguredPath("data/../etc/passwd"));
        assertRejected(() -> SafePathUtils.canonicalizeConfiguredPath(".."));
        assertRejected(() -> SafePathUtils.canonicalizeConfiguredPath("   "));
        assertRejected(() -> SafePathUtils.canonicalizeConfiguredPath(null));
    }

    @Test
    void requireWithin_acceptsChildrenAndRejectsEscapes(@TempDir Path tempDir) {
        Path base = tempDir.resolve("base");

        assertThat(SafePathUtils.requireWithin(base, base.resolve("report.json")))
                .isEqualTo(base.resolve("report.json").toAbsolutePath().normalize());
        assertRejected(() -> SafePathUtils.requireWithin(base, base.resolve("../escaped")));
    }

    private static void assertRejected(ThrowingCallable callable) {
        assertThatThrownBy(callable).isInstanceOf(IllegalArgumentException.class);
    }
}
