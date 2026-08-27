package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class UrlSafetyValidatorTest {

    @Test
    @DisplayName("Should reject null and blank URLs")
    void rejectsNullAndBlank() {
        assertFalse(UrlSafetyValidator.isSafeUrl(null));
        assertFalse(UrlSafetyValidator.isSafeUrl(""));
        assertFalse(UrlSafetyValidator.isSafeUrl("   "));
    }

    @Test
    @DisplayName("Should reject malformed URLs")
    void rejectsMalformedUrl() {
        assertFalse(UrlSafetyValidator.isSafeUrl("notAUrl"));
        assertFalse(UrlSafetyValidator.isSafeUrl("://missing-scheme"));
    }

    @ParameterizedTest
    @DisplayName("Should reject non-http/https schemes")
    @ValueSource(strings = {"file:///etc/passwd", "ftp://example.com/file", "gopher://evil.com"})
    void rejectsDisallowedSchemes(String url) {
        assertFalse(UrlSafetyValidator.isSafeUrl(url));
    }

    @ParameterizedTest
    @DisplayName("Should reject URLs targeting loopback addresses")
    @ValueSource(strings = {"http://127.0.0.1/", "http://127.0.0.2:8080/path"})
    void rejectsLoopback(String url) {
        assertFalse(UrlSafetyValidator.isSafeUrl(url));
    }

    @ParameterizedTest
    @DisplayName("Should reject URLs targeting link-local / cloud metadata endpoints")
    @ValueSource(
            strings = {
                "http://169.254.169.254/latest/meta-data",
                "http://169.254.170.2/credentials"
            })
    void rejectsLinkLocal(String url) {
        assertFalse(UrlSafetyValidator.isSafeUrl(url));
    }

    @ParameterizedTest
    @DisplayName("Should reject URLs targeting private RFC1918 ranges")
    @ValueSource(
            strings = {
                "http://10.0.0.1/internal",
                "http://172.16.0.1/admin",
                "http://192.168.1.1/router"
            })
    void rejectsPrivateRanges(String url) {
        assertFalse(UrlSafetyValidator.isSafeUrl(url));
    }

    @ParameterizedTest
    @DisplayName("Should reject IPv6 private/loopback addresses")
    @ValueSource(strings = {"http://[::1]/", "http://[::ffff:169.254.169.254]/"})
    void rejectsIPv6Private(String url) {
        assertFalse(UrlSafetyValidator.isSafeUrl(url));
    }

    @Test
    @DisplayName("Should identify loopback as private")
    void isPrivateLoopback() throws UnknownHostException {
        assertTrue(
                UrlSafetyValidator.isPrivateOrReservedAddress(
                        InetAddress.getByName("127.0.0.1")));
    }

    @Test
    @DisplayName("Should identify site-local as private")
    void isPrivateSiteLocal() throws UnknownHostException {
        assertTrue(
                UrlSafetyValidator.isPrivateOrReservedAddress(InetAddress.getByName("10.0.0.1")));
        assertTrue(
                UrlSafetyValidator.isPrivateOrReservedAddress(
                        InetAddress.getByName("172.16.0.1")));
        assertTrue(
                UrlSafetyValidator.isPrivateOrReservedAddress(
                        InetAddress.getByName("192.168.0.1")));
    }

    @Test
    @DisplayName("Should identify link-local (metadata) as private")
    void isPrivateLinkLocal() throws UnknownHostException {
        assertTrue(
                UrlSafetyValidator.isPrivateOrReservedAddress(
                        InetAddress.getByName("169.254.169.254")));
    }

    @Test
    @DisplayName("Should allow public IP addresses")
    void allowsPublicAddress() throws UnknownHostException {
        assertFalse(
                UrlSafetyValidator.isPrivateOrReservedAddress(InetAddress.getByName("8.8.8.8")));
        assertFalse(
                UrlSafetyValidator.isPrivateOrReservedAddress(InetAddress.getByName("1.1.1.1")));
    }
}
