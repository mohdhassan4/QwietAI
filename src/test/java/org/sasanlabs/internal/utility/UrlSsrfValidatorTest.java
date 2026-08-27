package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class UrlSsrfValidatorTest {

    private static Stream<Arguments> unsafeUrls() {
        return Stream.of(
                // Non-HTTP schemes
                Arguments.of("file:///etc/passwd"),
                Arguments.of("ftp://internal-server/data"),
                Arguments.of("gopher://localhost:25"),
                // Loopback addresses
                Arguments.of("http://127.0.0.1/admin"),
                Arguments.of("http://localhost/admin"),
                Arguments.of("http://[::1]/admin"),
                // Link-local / cloud metadata
                Arguments.of("http://169.254.169.254/latest/meta-data"),
                Arguments.of("http://[::ffff:169.254.169.254]/1.0"),
                // Private ranges
                Arguments.of("http://10.0.0.1/internal"),
                Arguments.of("http://172.16.0.1/internal"),
                Arguments.of("http://192.168.1.1/internal"),
                // Null / empty / invalid
                Arguments.of(""),
                Arguments.of("not-a-url"),
                Arguments.of("://missing-scheme"));
    }

    @ParameterizedTest
    @MethodSource("unsafeUrls")
    void rejectsUnsafeUrls(String url) {
        assertFalse(UrlSsrfValidator.isSafeUrl(url));
    }

    private static Stream<Arguments> safeUrls() {
        return Stream.of(
                Arguments.of("https://github.com/SasanLabs/VulnerableApp"),
                Arguments.of("https://gist.githubusercontent.com/raw/abc123"),
                Arguments.of("http://example.com/page"));
    }

    @ParameterizedTest
    @MethodSource("safeUrls")
    void allowsSafeUrls(String url) {
        assertTrue(UrlSsrfValidator.isSafeUrl(url));
    }
}
