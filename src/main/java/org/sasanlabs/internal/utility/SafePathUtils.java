package org.sasanlabs.internal.utility;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Helpers that keep filesystem access inside the directory it was meant to stay in (CWE-22).
 *
 * <p>Every check fails closed by throwing {@link IllegalArgumentException}.
 *
 * <p>Rejection messages name the broken rule and never echo the untrusted value back.
 */
public final class SafePathUtils {

    private static final String CURRENT_DIRECTORY = ".";
    private static final String PARENT_DIRECTORY = "..";
    private static final char NULL_BYTE = (char) 0;

    private SafePathUtils() {}

    /**
     * Resolves a single, request supplied file name inside {@code baseDir}.
     *
     * <p>Separators, {@code ".."}, absolute paths and symlink escapes are all refused.
     *
     * @param baseDir directory the returned path is guaranteed to live in.
     * @param childName plain file name to resolve.
     * @return the real, symlink resolved path of the requested file.
     * @throws IllegalArgumentException if the name is not a plain name inside {@code baseDir}.
     * @throws IOException if the base directory or the requested file cannot be read.
     */
    public static Path resolveChildWithin(Path baseDir, String childName) throws IOException {
        if (baseDir == null) {
            throw new IllegalArgumentException("base directory must not be null");
        }
        if (childName == null || childName.trim().isEmpty()) {
            throw new IllegalArgumentException("file name must not be null or blank");
        }
        rejectNullByte(childName);
        // Paths.get throws InvalidPathException, an IllegalArgumentException, on illegal names.
        Path child = Paths.get(childName);
        if (child.isAbsolute()
                || child.getNameCount() != 1
                || !child.getName(0).toString().equals(childName)
                || CURRENT_DIRECTORY.equals(childName)
                || PARENT_DIRECTORY.equals(childName)) {
            throw new IllegalArgumentException(
                    "file name must be a single path element without separators or '..'");
        }
        Path base = baseDir.toAbsolutePath().normalize();
        requireWithin(base, base.resolve(child));
        // Resolve symlinks as well, otherwise a link inside the base directory could still point
        // out of it. This also raises NoSuchFileException when the requested file is absent.
        Path realBase = base.toRealPath();
        return requireWithin(realBase, realBase.resolve(child).toRealPath());
    }

    /**
     * Canonicalises an operator configured path, refusing {@code ".."} segments.
     *
     * <p>Absolute paths and paths relative to the working directory stay supported, so a
     * misconfigured or injected property can no longer walk out of the directory it names.
     *
     * @param rawPath configured path.
     * @return the absolute, normalised form of {@code rawPath}.
     * @throws IllegalArgumentException if the path is blank or holds a {@code ".."} segment.
     */
    public static Path canonicalizeConfiguredPath(String rawPath) {
        if (rawPath == null || rawPath.trim().isEmpty()) {
            throw new IllegalArgumentException("path must not be null or blank");
        }
        rejectNullByte(rawPath);
        Path path = Paths.get(rawPath.trim());
        for (Path element : path) {
            if (PARENT_DIRECTORY.equals(element.toString())) {
                throw new IllegalArgumentException("path must not contain '..' segments");
            }
        }
        return path.toAbsolutePath().normalize();
    }

    /**
     * Asserts that {@code candidate} stays inside {@code baseDir} once both are canonicalised.
     *
     * @param baseDir directory {@code candidate} has to stay in.
     * @param candidate path to verify.
     * @return the absolute, normalised form of {@code candidate}.
     * @throws IllegalArgumentException if {@code candidate} escapes {@code baseDir}.
     */
    public static Path requireWithin(Path baseDir, Path candidate) {
        if (baseDir == null || candidate == null) {
            throw new IllegalArgumentException("base directory and candidate must not be null");
        }
        Path base = baseDir.toAbsolutePath().normalize();
        Path resolved = candidate.toAbsolutePath().normalize();
        if (!resolved.startsWith(base)) {
            throw new IllegalArgumentException(
                    "resolved path escapes the allowed base directory " + base);
        }
        return resolved;
    }

    private static void rejectNullByte(String value) {
        if (value.indexOf(NULL_BYTE) >= 0) {
            throw new IllegalArgumentException("path must not contain a null byte");
        }
    }
}
