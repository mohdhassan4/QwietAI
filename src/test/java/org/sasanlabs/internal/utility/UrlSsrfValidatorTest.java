package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class UrlSsrfValidatorTest {

    @Test
    void shouldBlockFileProtocol() {
        assertFalse(UrlSsrfValidator.isSafeUrl("file:///etc/passwd"));
    }

    @Test
    void shouldBlockFtpProtocol() {
        assertFalse(UrlSsrfValidator.isSafeUrl("ftp://example.com/file.txt"));
    }

    @Test
    void shouldBlockLoopbackAddress() {
        assertFalse(UrlSsrfValidator.isSafeUrl("http://127.0.0.1/admin"));
        assertFalse(UrlSsrfValidator.isSafeUrl("http://127.0.0.2/admin"));
    }

    @Test
    void shouldBlockLocalhostByName() {
        assertFalse(UrlSsrfValidator.isSafeUrl("http://localhost/admin"));
    }

    @Test
    void shouldBlockPrivateNetworks() {
        assertFalse(UrlSsrfValidator.isSafeUrl("http://10.0.0.1/internal"));
        assertFalse(UrlSsrfValidator.isSafeUrl("http://172.16.0.1/internal"));
        assertFalse(UrlSsrfValidator.isSafeUrl("http://192.168.1.1/admin"));
    }

    @Test
    void shouldBlockAwsMetadataService() {
        assertFalse(UrlSsrfValidator.isSafeUrl("http://169.254.169.254/latest/meta-data"));
    }

    @Test
    void shouldBlockIpv6Loopback() {
        assertFalse(UrlSsrfValidator.isSafeUrl("http://[::1]/admin"));
    }

    @Test
    void shouldAllowPublicHttpUrls() {
        assertTrue(UrlSsrfValidator.isSafeUrl("https://github.com/SasanLabs/VulnerableApp"));
        assertTrue(UrlSsrfValidator.isSafeUrl("https://gist.githubusercontent.com/raw/abc123"));
    }

    @Test
    void shouldRejectInvalidUrl() {
        assertFalse(UrlSsrfValidator.isSafeUrl("not a url"));
        assertFalse(UrlSsrfValidator.isSafeUrl(""));
    }

    @Test
    void shouldRejectNullScheme() {
        assertFalse(UrlSsrfValidator.isSafeUrl("://example.com"));
    }
}
