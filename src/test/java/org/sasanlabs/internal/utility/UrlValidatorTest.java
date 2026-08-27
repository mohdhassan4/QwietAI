package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class UrlValidatorTest {

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://127.0.0.1/secret",
                "http://127.0.0.1:8080/admin",
                "http://10.0.0.1/internal",
                "http://10.255.255.255/data",
                "http://172.16.0.1/private",
                "http://172.31.255.255/endpoint",
                "http://192.168.1.1/router",
                "http://192.168.0.100/local",
                "http://169.254.169.254/latest/meta-data",
                "http://169.254.170.2/credentials",
                "http://[::ffff:169.254.169.254]/metadata",
                "http://localhost/admin",
                "file:///etc/passwd",
                "ftp://internal.server/data",
                "gopher://internal/resource",
            })
    void rejectsInternalAndDisallowedUrls(String url) {
        assertFalse(UrlValidator.isSafeUrl(url));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "https://github.com/SasanLabs/VulnerableApp",
                "https://gist.githubusercontent.com/raw/abc123",
                "http://example.com/resource",
                "https://api.example.org/data",
            })
    void allowsPublicHttpUrls(String url) {
        assertTrue(UrlValidator.isSafeUrl(url));
    }

    @Test
    void rejectsNullOrInvalid() {
        assertFalse(UrlValidator.isSafeUrl(""));
        assertFalse(UrlValidator.isSafeUrl("not-a-url"));
        assertFalse(UrlValidator.isSafeUrl("://missing-scheme"));
    }

    @Test
    void rejectsFileProtocol() {
        assertFalse(UrlValidator.isSafeUrl("file:///etc/passwd"));
        assertFalse(UrlValidator.isSafeUrl("file:///C:/Windows/System32/config/sam"));
    }

    @Test
    void rejectsNonHttpSchemes() {
        assertFalse(UrlValidator.isSafeUrl("ftp://example.com/file"));
        assertFalse(UrlValidator.isSafeUrl("gopher://example.com/"));
        assertFalse(UrlValidator.isSafeUrl("dict://example.com/"));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://127.0.0.1/secret",
                "http://10.0.0.1/internal",
                "http://169.254.169.254/latest/meta-data",
                "file:///etc/passwd",
                "ftp://internal.server/data",
            })
    void getSafeUrl_rejectsUnsafeUrls(String url) {
        assertNull(UrlValidator.getSafeUrl(url));
    }

    @Test
    void getSafeUrl_returnsResolvedUrlForPublicHosts() {
        String result = UrlValidator.getSafeUrl("https://example.com/resource");
        assertNotNull(result);
        // The resolved URL should contain the path but use a resolved IP
        assertTrue(result.contains("/resource"));
        assertTrue(result.startsWith("https://"));
    }

    @Test
    void getSafeUrl_rejectsNullOrInvalid() {
        assertNull(UrlValidator.getSafeUrl(""));
        assertNull(UrlValidator.getSafeUrl("not-a-url"));
        assertNull(UrlValidator.getSafeUrl("://missing-scheme"));
    }
}
