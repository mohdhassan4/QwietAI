package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class SSRFValidatorTest {

    @Test
    void rejectsFileProtocol() {
        assertFalse(SSRFValidator.isSafeUrl("file:///etc/passwd"));
    }

    @Test
    void rejectsLoopbackAddress() {
        assertFalse(SSRFValidator.isSafeUrl("http://127.0.0.1/admin"));
        assertFalse(SSRFValidator.isSafeUrl("http://localhost/admin"));
    }

    @Test
    void rejectsPrivateNetworks() {
        assertFalse(SSRFValidator.isSafeUrl("http://10.0.0.1/internal"));
        assertFalse(SSRFValidator.isSafeUrl("http://172.16.0.1/internal"));
        assertFalse(SSRFValidator.isSafeUrl("http://192.168.1.1/internal"));
    }

    @Test
    void rejectsLinkLocalMetadata() {
        assertFalse(SSRFValidator.isSafeUrl("http://169.254.169.254/latest/meta-data"));
        assertFalse(SSRFValidator.isSafeUrl("http://169.254.170.2/credentials"));
    }

    @Test
    void rejectsInvalidUrl() {
        assertFalse(SSRFValidator.isSafeUrl("not-a-url"));
        assertFalse(SSRFValidator.isSafeUrl(""));
    }

    @Test
    void rejectsFtpScheme() {
        assertFalse(SSRFValidator.isSafeUrl("ftp://example.com/file"));
    }

    @Test
    void acceptsPublicHttpUrl() {
        assertTrue(SSRFValidator.isSafeUrl("https://github.com/SasanLabs/VulnerableApp"));
    }

    @Test
    void acceptsPublicHttpsUrl() {
        assertTrue(SSRFValidator.isSafeUrl("https://gist.githubusercontent.com/raw/abc123"));
    }
}
