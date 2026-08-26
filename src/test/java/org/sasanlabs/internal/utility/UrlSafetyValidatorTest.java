package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class UrlSafetyValidatorTest {

    @Test
    @DisplayName("Should reject file:// protocol URLs")
    void rejectsFileProtocol() {
        assertFalse(UrlSafetyValidator.isSafeUrl("file:///etc/passwd"));
        assertFalse(UrlSafetyValidator.isSafeUrl("file:///tmp/test.txt"));
    }

    @Test
    @DisplayName("Should reject ftp:// protocol URLs")
    void rejectsFtpProtocol() {
        assertFalse(UrlSafetyValidator.isSafeUrl("ftp://example.com/file"));
    }

    @Test
    @DisplayName("Should reject malformed URLs")
    void rejectsMalformedUrls() {
        assertFalse(UrlSafetyValidator.isSafeUrl("not a url"));
        assertFalse(UrlSafetyValidator.isSafeUrl(""));
        assertFalse(UrlSafetyValidator.isSafeUrl("://missing-scheme"));
    }

    @Test
    @DisplayName("Should reject loopback addresses")
    void rejectsLoopback() {
        assertFalse(UrlSafetyValidator.isSafeUrl("http://127.0.0.1/path"));
        assertFalse(UrlSafetyValidator.isSafeUrl("http://localhost/path"));
    }

    @Test
    @DisplayName("Should reject link-local metadata addresses")
    void rejectsLinkLocal() {
        assertFalse(UrlSafetyValidator.isSafeUrl("http://169.254.169.254/latest/meta-data"));
    }

    @Test
    @DisplayName("Should reject private network addresses")
    void rejectsPrivateNetworks() {
        assertFalse(UrlSafetyValidator.isSafeUrl("http://10.0.0.1/internal"));
        assertFalse(UrlSafetyValidator.isSafeUrl("http://172.16.0.1/internal"));
        assertFalse(UrlSafetyValidator.isSafeUrl("http://192.168.1.1/internal"));
    }

    @Test
    @DisplayName("Should allow legitimate public https URLs")
    void allowsPublicHttps() {
        assertTrue(UrlSafetyValidator.isSafeUrl("https://github.com/SasanLabs/VulnerableApp"));
        assertTrue(UrlSafetyValidator.isSafeUrl("https://www.google.com"));
    }

    @Test
    @DisplayName("Should allow legitimate public http URLs")
    void allowsPublicHttp() {
        assertTrue(UrlSafetyValidator.isSafeUrl("http://example.com/page"));
    }

    @Test
    @DisplayName("isInternalAddress should detect loopback")
    void detectsLoopbackAddress() throws UnknownHostException {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        assertTrue(UrlSafetyValidator.isInternalAddress(loopback));
    }

    @Test
    @DisplayName("isInternalAddress should detect site-local")
    void detectsSiteLocal() throws UnknownHostException {
        InetAddress siteLocal = InetAddress.getByName("192.168.1.1");
        assertTrue(UrlSafetyValidator.isInternalAddress(siteLocal));
    }

    @Test
    @DisplayName("isInternalAddress should detect link-local")
    void detectsLinkLocal() throws UnknownHostException {
        InetAddress linkLocal = InetAddress.getByName("169.254.169.254");
        assertTrue(UrlSafetyValidator.isInternalAddress(linkLocal));
    }

    @Test
    @DisplayName("isInternalAddress should not flag public IPs")
    void allowsPublicAddresses() throws UnknownHostException {
        InetAddress publicAddr = InetAddress.getByName("8.8.8.8");
        assertFalse(UrlSafetyValidator.isInternalAddress(publicAddr));
    }
}
