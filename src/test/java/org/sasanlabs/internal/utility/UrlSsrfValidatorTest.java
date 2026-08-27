package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.MalformedURLException;
import java.net.URL;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class UrlSsrfValidatorTest {

    @ParameterizedTest
    @ValueSource(
            strings = {
                "file:///etc/passwd",
                "ftp://example.com/file",
                "gopher://example.com",
                "jar:file:///tmp/test.jar!/test.txt"
            })
    void validateUrl_rejectsNonHttpSchemes(String url) {
        assertThrows(SecurityException.class, () -> UrlSsrfValidator.validateUrl(url));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://127.0.0.1/path",
                "http://127.0.0.1:8080/path",
                "https://127.0.0.1/admin",
                "http://10.0.0.1/internal",
                "http://10.255.255.255/internal",
                "http://172.16.0.1/internal",
                "http://172.31.255.255/internal",
                "http://192.168.1.1/admin",
                "http://192.168.0.1/internal",
                "http://169.254.169.254/latest/meta-data",
                "http://169.254.170.2/credentials"
            })
    void validateUrl_rejectsPrivateIpAddresses(String url) {
        assertThrows(SecurityException.class, () -> UrlSsrfValidator.validateUrl(url));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://[::1]/path",
                "http://[::ffff:127.0.0.1]/path",
                "http://[::ffff:169.254.169.254]/meta"
            })
    void validateUrl_rejectsPrivateIpv6Addresses(String url) {
        assertThrows(SecurityException.class, () -> UrlSsrfValidator.validateUrl(url));
    }

    @Test
    void validateUrl_rejectsEmptyHost() {
        assertThrows(
                Exception.class, () -> UrlSsrfValidator.validateUrl("http:///path/only"));
    }

    @Test
    void validateUrl_rejectsMalformedUrl() {
        assertThrows(
                MalformedURLException.class,
                () -> UrlSsrfValidator.validateUrl("not-a-valid-url"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://localhost/path", "https://localhost:8080/path"})
    void validateUrl_rejectsLocalhost(String url) {
        assertThrows(SecurityException.class, () -> UrlSsrfValidator.validateUrl(url));
    }

    @Test
    void validateUrl_acceptsPublicHttpUrl() {
        URL result =
                assertDoesNotThrow(
                        () -> UrlSsrfValidator.validateUrl("http://93.184.216.34/index.html"));
        assertEquals("http", result.getProtocol());
        assertEquals("93.184.216.34", result.getHost());
    }

    @Test
    void validateUrl_acceptsPublicHttpsUrl() {
        URL result =
                assertDoesNotThrow(
                        () -> UrlSsrfValidator.validateUrl("https://93.184.216.34/index.html"));
        assertEquals("https", result.getProtocol());
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://127.0.0.1/",
                "http://169.254.169.254/meta",
                "file:///etc/passwd",
                "ftp://internal.host/"
            })
    void isSafeUrl_returnsFalseForUnsafeUrls(String url) {
        assertFalse(UrlSsrfValidator.isSafeUrl(url));
    }

    @Test
    void isSafeUrl_returnsTrueForPublicIp() {
        assertTrue(UrlSsrfValidator.isSafeUrl("https://93.184.216.34/page"));
    }
}
