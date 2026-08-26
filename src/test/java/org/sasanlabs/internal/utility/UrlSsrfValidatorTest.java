package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class UrlSsrfValidatorTest {

    @ParameterizedTest
    @ValueSource(
            strings = {
                "file:///etc/passwd",
                "ftp://internal.server/file",
                "gopher://evil.com/payload",
                "jar:file:///tmp/test.jar!/entry"
            })
    void rejectsNonHttpSchemes(String url) {
        assertFalse(UrlSsrfValidator.isUrlSafeFromSsrf(url));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://localhost/admin",
                "http://localhost:8080/api",
                "https://localhost/secret",
                "http://localhost.localdomain/path"
            })
    void rejectsLocalhostHostnames(String url) {
        assertFalse(UrlSsrfValidator.isUrlSafeFromSsrf(url));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://127.0.0.1/admin",
                "http://127.0.0.2:8080/api",
                "http://10.0.0.1/internal",
                "http://10.255.255.255/api",
                "http://172.16.0.1/private",
                "http://172.31.255.255/api",
                "http://192.168.0.1/admin",
                "http://192.168.1.100/api",
                "http://169.254.169.254/latest/meta-data",
                "http://[::1]/admin"
            })
    void rejectsPrivateAndInternalIPs(String url) {
        assertFalse(UrlSsrfValidator.isUrlSafeFromSsrf(url));
    }

    @Test
    void rejectsInvalidUrl() {
        assertFalse(UrlSsrfValidator.isUrlSafeFromSsrf("not a url"));
        assertFalse(UrlSsrfValidator.isUrlSafeFromSsrf(""));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "https://github.com/SasanLabs/VulnerableApp",
                "https://gist.githubusercontent.com/raw/abc123",
                "http://example.com/api/data"
            })
    void acceptsLegitimateExternalUrls(String url) {
        assertTrue(UrlSsrfValidator.isUrlSafeFromSsrf(url));
    }
}
