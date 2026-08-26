package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.net.UnknownHostException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class UrlSafetyValidatorTest {

    @ParameterizedTest
    @ValueSource(
            strings = {
                "file:///etc/passwd",
                "file:///tmp/test.txt",
                "ftp://internal-server/file",
                "gopher://evil.com/payload",
                "jar:file:///tmp/test.jar!/entry"
            })
    void rejectsNonHttpSchemes(String url) {
        assertFalse(UrlSafetyValidator.isUrlSafeForServerSideRequest(url));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://127.0.0.1/secret",
                "http://127.0.0.1:8080/admin",
                "https://127.0.0.1/api",
                "http://127.1.2.3/internal"
            })
    void rejectsLoopbackAddresses(String url) {
        assertFalse(UrlSafetyValidator.isUrlSafeForServerSideRequest(url));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://10.0.0.1/internal",
                "http://10.255.255.255/data",
                "http://172.16.0.1/admin",
                "http://172.31.255.255/secret",
                "http://192.168.0.1/config",
                "http://192.168.1.100/data"
            })
    void rejectsPrivateAddresses(String url) {
        assertFalse(UrlSafetyValidator.isUrlSafeForServerSideRequest(url));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://169.254.169.254/latest/meta-data",
                "http://169.254.169.254/1.0",
                "http://169.254.0.1/something"
            })
    void rejectsLinkLocalAndMetadataAddresses(String url) {
        assertFalse(UrlSafetyValidator.isUrlSafeForServerSideRequest(url));
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://[::1]/secret", "http://[::1]:8080/admin"})
    void rejectsIpv6Loopback(String url) {
        assertFalse(UrlSafetyValidator.isUrlSafeForServerSideRequest(url));
    }

    @Test
    void rejectsNullAndEmpty() {
        assertFalse(UrlSafetyValidator.isUrlSafeForServerSideRequest(null));
        assertFalse(UrlSafetyValidator.isUrlSafeForServerSideRequest(""));
    }

    @Test
    void rejectsMalformedUrl() {
        assertFalse(UrlSafetyValidator.isUrlSafeForServerSideRequest("not-a-url"));
        assertFalse(UrlSafetyValidator.isUrlSafeForServerSideRequest("://missing-scheme"));
    }

    @Test
    void rejectsUnresolvableHost() {
        assertFalse(
                UrlSafetyValidator.isUrlSafeForServerSideRequest(
                        "http://this-host-definitely-does-not-exist-xyzzy.invalid/path"));
    }

    @Test
    void isAddressSafe_rejectsLoopback() throws UnknownHostException {
        InetAddress loopback = InetAddress.getByName("127.0.0.1");
        assertFalse(UrlSafetyValidator.isAddressSafe(loopback));
    }

    @Test
    void isAddressSafe_rejectsPrivate10() throws UnknownHostException {
        InetAddress addr = InetAddress.getByName("10.0.0.1");
        assertFalse(UrlSafetyValidator.isAddressSafe(addr));
    }

    @Test
    void isAddressSafe_rejectsPrivate172() throws UnknownHostException {
        InetAddress addr = InetAddress.getByName("172.16.0.1");
        assertFalse(UrlSafetyValidator.isAddressSafe(addr));
    }

    @Test
    void isAddressSafe_rejectsPrivate192() throws UnknownHostException {
        InetAddress addr = InetAddress.getByName("192.168.1.1");
        assertFalse(UrlSafetyValidator.isAddressSafe(addr));
    }

    @Test
    void isAddressSafe_rejectsLinkLocal() throws UnknownHostException {
        InetAddress addr = InetAddress.getByName("169.254.169.254");
        assertFalse(UrlSafetyValidator.isAddressSafe(addr));
    }

    @Test
    void isAddressSafe_rejectsIpv6Loopback() throws UnknownHostException {
        InetAddress addr = InetAddress.getByName("::1");
        assertFalse(UrlSafetyValidator.isAddressSafe(addr));
    }

    @Test
    void isAddressSafe_allowsPublicIp() throws UnknownHostException {
        // Use a well-known public IP (Google DNS)
        InetAddress addr = InetAddress.getByName("8.8.8.8");
        assertTrue(UrlSafetyValidator.isAddressSafe(addr));
    }

    @Test
    void isAddressSafe_rejects172OutsideRange() throws UnknownHostException {
        // 172.32.0.1 is NOT in the 172.16.0.0/12 range, so it is public
        InetAddress addr = InetAddress.getByName("172.32.0.1");
        assertTrue(UrlSafetyValidator.isAddressSafe(addr));
    }
}
