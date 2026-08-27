package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SsrfProtectionUtilsTest {

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://169.254.169.254/latest/meta-data",
                "http://169.254.170.2/credentials",
                "http://127.0.0.1/admin",
                "http://localhost/admin",
                "http://10.0.0.1/internal",
                "http://172.16.0.1/internal",
                "http://172.31.255.255/internal",
                "http://192.168.1.1/internal",
                "http://[::1]/admin",
                "http://[::ffff:169.254.169.254]/latest",
                "http://[0:0:0:0:0:ffff:169.254.169.254]/latest",
                "file:///etc/passwd",
                "ftp://example.com/file",
                "gopher://example.com/",
            })
    void shouldRejectUnsafeUrls(String url) {
        assertFalse(SsrfProtectionUtils.isUrlSafe(url));
    }

    @Test
    void shouldRejectNullUrl() {
        assertFalse(SsrfProtectionUtils.isUrlSafe(null));
    }

    @Test
    void shouldRejectEmptyUrl() {
        assertFalse(SsrfProtectionUtils.isUrlSafe(""));
    }

    @Test
    void shouldRejectMalformedUrl() {
        assertFalse(SsrfProtectionUtils.isUrlSafe("not-a-url"));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "https://github.com/SasanLabs/VulnerableApp",
                "https://www.google.com",
                "http://example.com/page",
                "https://gist.githubusercontent.com/raw/abc123",
            })
    void shouldAllowSafeExternalUrls(String url) {
        assertTrue(SsrfProtectionUtils.isUrlSafe(url));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "https://github.com/SasanLabs/VulnerableApp",
                "https://www.google.com",
                "http://example.com/page",
                "https://gist.githubusercontent.com/raw/abc123",
            })
    void sanitizeUrlShouldReturnValidatedUrlForSafeUrls(String urlString) {
        URL result = SsrfProtectionUtils.sanitizeUrl(urlString);
        assertNotNull(result);
        assertTrue(result.toString().startsWith("http"));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://169.254.169.254/latest/meta-data",
                "http://127.0.0.1/admin",
                "http://localhost/admin",
                "http://10.0.0.1/internal",
                "file:///etc/passwd",
                "ftp://example.com/file",
            })
    void sanitizeUrlShouldReturnNullForUnsafeUrls(String urlString) {
        assertNull(SsrfProtectionUtils.sanitizeUrl(urlString));
    }

    @Test
    void sanitizeUrlShouldReturnNullForNullInput() {
        assertNull(SsrfProtectionUtils.sanitizeUrl(null));
    }

    @Test
    void sanitizeUrlShouldReturnNullForEmptyInput() {
        assertNull(SsrfProtectionUtils.sanitizeUrl(""));
    }

    @Test
    void sanitizeUrlShouldReturnNullForMalformedInput() {
        assertNull(SsrfProtectionUtils.sanitizeUrl("not-a-url"));
    }
}
