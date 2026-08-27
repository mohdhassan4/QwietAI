package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.net.URL;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class UrlValidationUtilsTest {

    @Test
    void validateUrl_nullUrl_throwsException() {
        assertThrows(IllegalArgumentException.class, () -> UrlValidationUtils.validateUrl(null));
    }

    @Test
    void validateUrl_emptyUrl_throwsException() {
        assertThrows(IllegalArgumentException.class, () -> UrlValidationUtils.validateUrl(""));
    }

    @Test
    void validateUrl_blankUrl_throwsException() {
        assertThrows(IllegalArgumentException.class, () -> UrlValidationUtils.validateUrl("   "));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "file:///etc/passwd",
                "ftp://example.com/file",
                "gopher://example.com",
                "jar:file:///tmp/test.jar!/test.txt"
            })
    void validateUrl_disallowedScheme_throwsException(String url) {
        assertThrows(IllegalArgumentException.class, () -> UrlValidationUtils.validateUrl(url));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://127.0.0.1/path",
                "http://127.0.0.1:8080/path",
                "https://127.0.0.1/path"
            })
    void validateUrl_loopbackAddress_throwsException(String url) {
        assertThrows(IllegalArgumentException.class, () -> UrlValidationUtils.validateUrl(url));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://169.254.169.254/latest/meta-data",
                "http://169.254.1.1/path"
            })
    void validateUrl_linkLocalAddress_throwsException(String url) {
        assertThrows(IllegalArgumentException.class, () -> UrlValidationUtils.validateUrl(url));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://10.0.0.1/path",
                "http://172.16.0.1/path",
                "http://192.168.1.1/path"
            })
    void validateUrl_siteLocalAddress_throwsException(String url) {
        assertThrows(IllegalArgumentException.class, () -> UrlValidationUtils.validateUrl(url));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://[::ffff:169.254.169.254]/path",
                "http://[::ffff:127.0.0.1]/path",
                "http://[::ffff:10.0.0.1]/path",
                "http://[::ffff:192.168.1.1]/path"
            })
    void validateUrl_ipv4MappedIpv6InternalAddress_throwsException(String url) {
        assertThrows(IllegalArgumentException.class, () -> UrlValidationUtils.validateUrl(url));
    }

    @Test
    void validateUrl_validPublicHttpUrl_returnsUrl() {
        URL result = UrlValidationUtils.validateUrl("http://1.1.1.1/path");
        assertNotNull(result);
        assertEquals("http", result.getProtocol());
        assertEquals("1.1.1.1", result.getHost());
    }

    @Test
    void validateUrl_validPublicHttpsUrl_returnsUrl() {
        URL result = UrlValidationUtils.validateUrl("https://8.8.8.8/path");
        assertNotNull(result);
        assertEquals("https", result.getProtocol());
        assertEquals("8.8.8.8", result.getHost());
    }

    @Test
    void validateUrl_invalidUrl_throwsException() {
        assertThrows(
                IllegalArgumentException.class,
                () -> UrlValidationUtils.validateUrl("not-a-url"));
    }
}
