package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class SsrfProtectionUtilsTest {

    @Test
    void rejectsFileProtocol() {
        assertFalse(SsrfProtectionUtils.isUrlSafeFromSsrf("file:///etc/passwd"));
    }

    @Test
    void rejectsInvalidUrl() {
        assertFalse(SsrfProtectionUtils.isUrlSafeFromSsrf("not-a-url"));
    }

    @Test
    void rejectsLoopbackIpv4() {
        assertFalse(SsrfProtectionUtils.isUrlSafeFromSsrf("http://127.0.0.1/path"));
    }

    @Test
    void rejectsLinkLocal() {
        assertFalse(SsrfProtectionUtils.isUrlSafeFromSsrf("http://169.254.169.254/latest"));
    }

    @Test
    void rejectsPrivate10Network() {
        assertFalse(SsrfProtectionUtils.isUrlSafeFromSsrf("http://10.0.0.1/internal"));
    }

    @Test
    void rejectsPrivate172Network() {
        assertFalse(SsrfProtectionUtils.isUrlSafeFromSsrf("http://172.16.0.1/internal"));
    }

    @Test
    void rejectsPrivate192Network() {
        assertFalse(SsrfProtectionUtils.isUrlSafeFromSsrf("http://192.168.1.1/internal"));
    }

    @Test
    void rejectsIpv4MappedIpv6LinkLocal() {
        assertFalse(
                SsrfProtectionUtils.isUrlSafeFromSsrf(
                        "http://[::ffff:169.254.169.254]/latest"));
    }

    @Test
    void rejectsIpv6Loopback() {
        assertFalse(SsrfProtectionUtils.isUrlSafeFromSsrf("http://[::1]/path"));
    }

    @Test
    void rejectsEmptyHost() {
        assertFalse(SsrfProtectionUtils.isUrlSafeFromSsrf("http:///path"));
    }

    @Test
    void rejectsNullInput() {
        assertFalse(SsrfProtectionUtils.isUrlSafeFromSsrf(null));
    }

    @Test
    void acceptsPublicHttpsUrl() {
        // This test requires DNS resolution; github.com resolves to a public IP
        assertTrue(SsrfProtectionUtils.isUrlSafeFromSsrf("https://github.com/test"));
    }
}
