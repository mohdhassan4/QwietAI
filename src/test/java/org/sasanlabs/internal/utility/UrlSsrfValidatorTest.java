package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.Optional;
import org.junit.jupiter.api.Test;

class UrlSsrfValidatorTest {

    @Test
    void rejectsNullAndEmpty() {
        assertFalse(UrlSsrfValidator.isSafeFromSsrf(null));
        assertFalse(UrlSsrfValidator.isSafeFromSsrf(""));
    }

    @Test
    void rejectsFileProtocol() {
        assertFalse(UrlSsrfValidator.isSafeFromSsrf("file:///etc/passwd"));
        assertFalse(UrlSsrfValidator.isSafeFromSsrf("file:///tmp/test.txt"));
    }

    @Test
    void rejectsFtpProtocol() {
        assertFalse(UrlSsrfValidator.isSafeFromSsrf("ftp://example.com/file.txt"));
    }

    @Test
    void rejectsGopherProtocol() {
        assertFalse(UrlSsrfValidator.isSafeFromSsrf("gopher://evil.com/"));
    }

    @Test
    void rejectsLoopbackAddresses() {
        assertFalse(UrlSsrfValidator.isSafeFromSsrf("http://127.0.0.1/"));
        assertFalse(UrlSsrfValidator.isSafeFromSsrf("http://127.0.0.1:8080/admin"));
    }

    @Test
    void rejectsLinkLocalAddresses() {
        assertFalse(UrlSsrfValidator.isSafeFromSsrf("http://169.254.169.254/latest/meta-data"));
        assertFalse(UrlSsrfValidator.isSafeFromSsrf("http://169.254.170.2/"));
    }

    @Test
    void rejectsPrivateNetworkAddresses() {
        assertFalse(UrlSsrfValidator.isSafeFromSsrf("http://10.0.0.1/"));
        assertFalse(UrlSsrfValidator.isSafeFromSsrf("http://172.16.0.1/"));
        assertFalse(UrlSsrfValidator.isSafeFromSsrf("http://192.168.1.1/"));
    }

    @Test
    void rejectsIpv6MappedInternalAddresses() {
        assertFalse(
                UrlSsrfValidator.isSafeFromSsrf("http://[::ffff:169.254.169.254]/latest"));
    }

    @Test
    void rejectsMalformedUrls() {
        assertFalse(UrlSsrfValidator.isSafeFromSsrf("not-a-url"));
        assertFalse(UrlSsrfValidator.isSafeFromSsrf("://missing-scheme"));
    }

    @Test
    void allowsPublicHttpUrls() {
        assertTrue(UrlSsrfValidator.isSafeFromSsrf("https://github.com/SasanLabs"));
        assertTrue(UrlSsrfValidator.isSafeFromSsrf("https://example.com/path"));
        assertTrue(UrlSsrfValidator.isSafeFromSsrf("http://example.com/"));
    }

    @Test
    void allowsPublicHttpsUrls() {
        assertTrue(
                UrlSsrfValidator.isSafeFromSsrf(
                        "https://gist.githubusercontent.com/raw/abc123"));
    }

    @Test
    void getValidatedUriReturnsEmptyForUnsafeUrls() {
        assertEquals(Optional.empty(), UrlSsrfValidator.getValidatedUri(null));
        assertEquals(Optional.empty(), UrlSsrfValidator.getValidatedUri(""));
        assertEquals(Optional.empty(), UrlSsrfValidator.getValidatedUri("file:///etc/passwd"));
        assertEquals(Optional.empty(), UrlSsrfValidator.getValidatedUri("http://127.0.0.1/"));
        assertEquals(Optional.empty(), UrlSsrfValidator.getValidatedUri("http://10.0.0.1/"));
    }

    @Test
    void getValidatedUriReturnsSanitizedUriForSafeUrls() {
        Optional<URI> result = UrlSsrfValidator.getValidatedUri("https://example.com/path?q=1");
        assertTrue(result.isPresent());
        assertEquals("https", result.get().getScheme());
        assertEquals("example.com", result.get().getHost());
        assertEquals("/path", result.get().getPath());
        assertEquals("q=1", result.get().getQuery());
    }

    @Test
    void getValidatedUriPreservesPort() {
        Optional<URI> result =
                UrlSsrfValidator.getValidatedUri("https://example.com:8443/api");
        assertTrue(result.isPresent());
        assertEquals(8443, result.get().getPort());
        assertEquals("/api", result.get().getPath());
    }
}
