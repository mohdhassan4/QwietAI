package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

class SsrfUrlValidatorTest {

    @Test
    void rejectsFileProtocol() {
        assertFalse(SsrfUrlValidator.isSafeFromSsrf("file:///etc/passwd"));
    }

    @Test
    void rejectsLoopbackIPv4() {
        assertFalse(SsrfUrlValidator.isSafeFromSsrf("http://127.0.0.1/admin"));
    }

    @Test
    void rejectsLoopbackIPv6() {
        assertFalse(SsrfUrlValidator.isSafeFromSsrf("http://[::1]/admin"));
    }

    @Test
    void rejectsLinkLocalIPv4() {
        assertFalse(SsrfUrlValidator.isSafeFromSsrf("http://169.254.169.254/latest/meta-data"));
    }

    @Test
    void rejectsPrivate10Network() {
        assertFalse(SsrfUrlValidator.isSafeFromSsrf("http://10.0.0.1/internal"));
    }

    @Test
    void rejectsPrivate172Network() {
        assertFalse(SsrfUrlValidator.isSafeFromSsrf("http://172.16.0.1/internal"));
    }

    @Test
    void rejectsPrivate192Network() {
        assertFalse(SsrfUrlValidator.isSafeFromSsrf("http://192.168.1.1/internal"));
    }

    @Test
    void rejectsIPv4MappedIPv6LinkLocal() {
        assertFalse(
                SsrfUrlValidator.isSafeFromSsrf("http://[::ffff:169.254.169.254]/latest"));
    }

    @Test
    void rejectsIPv4MappedIPv6Private() {
        assertFalse(SsrfUrlValidator.isSafeFromSsrf("http://[::ffff:10.0.0.1]/admin"));
    }

    @Test
    void rejectsFtpProtocol() {
        assertFalse(SsrfUrlValidator.isSafeFromSsrf("ftp://example.com/file"));
    }

    @Test
    void rejectsInvalidUrl() {
        assertFalse(SsrfUrlValidator.isSafeFromSsrf("not-a-url"));
    }

    @Test
    void rejectsEmptyHost() {
        assertFalse(SsrfUrlValidator.isSafeFromSsrf("http:///path"));
    }
}
