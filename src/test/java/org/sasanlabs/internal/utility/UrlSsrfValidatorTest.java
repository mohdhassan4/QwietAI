package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class UrlSsrfValidatorTest {

    @Test
    @DisplayName("Should reject null and blank URLs")
    void rejectsNullAndBlank() {
        assertFalse(UrlSsrfValidator.isSafeUrl(null));
        assertFalse(UrlSsrfValidator.isSafeUrl(""));
        assertFalse(UrlSsrfValidator.isSafeUrl("   "));
    }

    @Test
    @DisplayName("Should reject malformed URLs")
    void rejectsMalformedUrl() {
        assertFalse(UrlSsrfValidator.isSafeUrl("not-a-url"));
        assertFalse(UrlSsrfValidator.isSafeUrl("://missing-scheme"));
    }

    @Test
    @DisplayName("Should reject file:// scheme")
    void rejectsFileScheme() {
        assertFalse(UrlSsrfValidator.isSafeUrl("file:///etc/passwd"));
        assertFalse(UrlSsrfValidator.isSafeUrl("file:///tmp/test.txt"));
    }

    @Test
    @DisplayName("Should reject ftp:// and other non-HTTP schemes")
    void rejectsNonHttpSchemes() {
        assertFalse(UrlSsrfValidator.isSafeUrl("ftp://example.com/file"));
        assertFalse(UrlSsrfValidator.isSafeUrl("gopher://example.com"));
        assertFalse(UrlSsrfValidator.isSafeUrl("dict://example.com"));
    }

    @Test
    @DisplayName("Should reject loopback addresses")
    void rejectsLoopback() {
        assertFalse(UrlSsrfValidator.isSafeUrl("http://127.0.0.1/admin"));
        assertFalse(UrlSsrfValidator.isSafeUrl("http://127.0.0.2/admin"));
        assertFalse(UrlSsrfValidator.isSafeUrl("http://localhost/admin"));
    }

    @Test
    @DisplayName("Should reject private network addresses (10.x, 172.16-31.x, 192.168.x)")
    void rejectsPrivateNetworks() {
        assertFalse(UrlSsrfValidator.isSafeUrl("http://10.0.0.1/internal"));
        assertFalse(UrlSsrfValidator.isSafeUrl("http://172.16.0.1/internal"));
        assertFalse(UrlSsrfValidator.isSafeUrl("http://192.168.1.1/internal"));
    }

    @Test
    @DisplayName("Should reject cloud metadata endpoint (169.254.169.254)")
    void rejectsMetadataEndpoint() {
        assertFalse(UrlSsrfValidator.isSafeUrl("http://169.254.169.254/latest/meta-data"));
        assertFalse(UrlSsrfValidator.isSafeUrl("http://169.254.170.2/credentials"));
    }

    @Test
    @DisplayName("Should reject IPv6 loopback and link-local")
    void rejectsIpv6Internal() {
        assertFalse(UrlSsrfValidator.isSafeUrl("http://[::1]/admin"));
        assertFalse(UrlSsrfValidator.isSafeUrl("http://[::ffff:127.0.0.1]/admin"));
        assertFalse(UrlSsrfValidator.isSafeUrl("http://[::ffff:169.254.169.254]/latest"));
    }

    @Test
    @DisplayName("Should allow legitimate external HTTPS URLs")
    void allowsExternalHttps() {
        assertTrue(UrlSsrfValidator.isSafeUrl("https://github.com/SasanLabs/VulnerableApp"));
        assertTrue(UrlSsrfValidator.isSafeUrl("https://gist.githubusercontent.com/raw/abc123"));
    }

    @Test
    @DisplayName("Should allow legitimate external HTTP URLs")
    void allowsExternalHttp() {
        assertTrue(UrlSsrfValidator.isSafeUrl("http://example.com/page"));
    }
}
