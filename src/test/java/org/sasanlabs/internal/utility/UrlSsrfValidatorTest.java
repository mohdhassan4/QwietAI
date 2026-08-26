package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class UrlSsrfValidatorTest {

    private static Stream<Arguments> blockedUrls() {
        return Stream.of(
                Arguments.of(null, "null URL"),
                Arguments.of("", "empty URL"),
                Arguments.of("invalidUrl", "malformed URL"),
                Arguments.of("file:///etc/passwd", "file protocol"),
                Arguments.of("ftp://example.com/file", "ftp protocol"),
                Arguments.of("http://127.0.0.1/admin", "loopback IPv4"),
                Arguments.of("http://127.0.0.2:8080/", "loopback range"),
                Arguments.of("http://10.0.0.1/internal", "private 10.x"),
                Arguments.of("http://172.16.0.1/internal", "private 172.16.x"),
                Arguments.of("http://192.168.1.1/internal", "private 192.168.x"),
                Arguments.of("http://169.254.169.254/latest/meta-data", "link-local metadata"),
                Arguments.of("http://[::1]/admin", "IPv6 loopback"),
                Arguments.of("http://0.0.0.0/", "any local address"));
    }

    @ParameterizedTest(name = "should block: {1}")
    @MethodSource("blockedUrls")
    void shouldBlockInternalUrls(String url, String description) {
        assertFalse(UrlSsrfValidator.isSafeUrl(url));
    }

    private static Stream<Arguments> allowedUrls() {
        return Stream.of(
                Arguments.of("https://github.com/SasanLabs/VulnerableApp", "public HTTPS"),
                Arguments.of("http://example.com/page", "public HTTP"),
                Arguments.of(
                        "https://gist.githubusercontent.com/raw/abc123",
                        "public gist URL"));
    }

    @ParameterizedTest(name = "should allow: {1}")
    @MethodSource("allowedUrls")
    void shouldAllowPublicUrls(String url, String description) {
        assertTrue(UrlSsrfValidator.isSafeUrl(url));
    }
}
