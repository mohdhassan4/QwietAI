package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class UrlSsrfValidatorTest {

    @Test
    @DisplayName("Should reject null and blank URLs")
    void rejectsNullAndBlank() {
        assertFalse(UrlSsrfValidator.isUrlSafeForServerSideRequest(null));
        assertFalse(UrlSsrfValidator.isUrlSafeForServerSideRequest(""));
        assertFalse(UrlSsrfValidator.isUrlSafeForServerSideRequest("   "));
    }

    @Test
    @DisplayName("Should reject non-http/https schemes")
    void rejectsNonHttpSchemes() {
        assertFalse(UrlSsrfValidator.isUrlSafeForServerSideRequest("file:///etc/passwd"));
        assertFalse(UrlSsrfValidator.isUrlSafeForServerSideRequest("ftp://example.com/file"));
        assertFalse(UrlSsrfValidator.isUrlSafeForServerSideRequest("gopher://internal:25"));
    }

    @Test
    @DisplayName("Should reject loopback addresses")
    void rejectsLoopback() {
        assertFalse(UrlSsrfValidator.isUrlSafeForServerSideRequest("http://127.0.0.1/admin"));
        assertFalse(UrlSsrfValidator.isUrlSafeForServerSideRequest("http://127.0.0.2/admin"));
        assertFalse(UrlSsrfValidator.isUrlSafeForServerSideRequest("http://localhost/admin"));
    }

    @Test
    @DisplayName("Should reject link-local/metadata addresses")
    void rejectsLinkLocal() {
        assertFalse(
                UrlSsrfValidator.isUrlSafeForServerSideRequest(
                        "http://169.254.169.254/latest/meta-data"));
        assertFalse(
                UrlSsrfValidator.isUrlSafeForServerSideRequest("http://169.254.170.2/credentials"));
    }

    @Test
    @DisplayName("Should reject private network addresses")
    void rejectsPrivateNetworks() {
        assertFalse(UrlSsrfValidator.isUrlSafeForServerSideRequest("http://10.0.0.1/internal"));
        assertFalse(UrlSsrfValidator.isUrlSafeForServerSideRequest("http://172.16.0.1/internal"));
        assertFalse(
                UrlSsrfValidator.isUrlSafeForServerSideRequest("http://192.168.1.1/internal"));
    }

    @Test
    @DisplayName("Should reject malformed URLs")
    void rejectsMalformed() {
        assertFalse(UrlSsrfValidator.isUrlSafeForServerSideRequest("not-a-url"));
        assertFalse(UrlSsrfValidator.isUrlSafeForServerSideRequest("http://"));
    }

    @Test
    @DisplayName("Should accept valid public HTTPS URLs")
    void acceptsPublicHttps() {
        // These resolve to public IPs
        assertTrue(
                UrlSsrfValidator.isUrlSafeForServerSideRequest(
                        "https://github.com/SasanLabs/VulnerableApp"));
        assertTrue(
                UrlSsrfValidator.isUrlSafeForServerSideRequest(
                        "https://gist.githubusercontent.com/raw/abc123"));
    }

    @Test
    @DisplayName("Should accept valid public HTTP URLs")
    void acceptsPublicHttp() {
        assertTrue(UrlSsrfValidator.isUrlSafeForServerSideRequest("http://example.com/page"));
    }
}
