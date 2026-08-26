package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URL;
import java.util.Optional;
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

    @Test
    void validateAndRebuildUrl_rejectsInvalidUrl() {
        assertEquals(Optional.empty(), SSRFValidator.validateAndRebuildUrl("not-a-url"));
        assertEquals(Optional.empty(), SSRFValidator.validateAndRebuildUrl(""));
    }

    @Test
    void validateAndRebuildUrl_rejectsFileProtocol() {
        assertEquals(Optional.empty(), SSRFValidator.validateAndRebuildUrl("file:///etc/passwd"));
    }

    @Test
    void validateAndRebuildUrl_rejectsPrivateAddresses() {
        assertEquals(Optional.empty(), SSRFValidator.validateAndRebuildUrl("http://127.0.0.1/x"));
        assertEquals(Optional.empty(), SSRFValidator.validateAndRebuildUrl("http://10.0.0.1/x"));
        assertEquals(
                Optional.empty(),
                SSRFValidator.validateAndRebuildUrl("http://169.254.169.254/latest"));
    }

    @Test
    void validateAndRebuildUrl_returnsRebuiltUrlForPublicHost() throws Exception {
        String input = "https://github.com/SasanLabs/VulnerableApp";
        Optional<URL> result = SSRFValidator.validateAndRebuildUrl(input);
        assertTrue(result.isPresent());
        URL rebuilt = result.get();
        assertEquals("https", rebuilt.getProtocol());
        assertEquals("github.com", rebuilt.getHost());
        assertEquals("/SasanLabs/VulnerableApp", rebuilt.getPath());
    }

    @Test
    void validateAndRebuildUrl_preservesQueryAndPort() throws Exception {
        String input = "https://example.com:8443/path?q=1&b=2";
        Optional<URL> result = SSRFValidator.validateAndRebuildUrl(input);
        assertTrue(result.isPresent());
        URL rebuilt = result.get();
        assertEquals(8443, rebuilt.getPort());
        assertEquals("/path", rebuilt.getPath());
        assertEquals("q=1&b=2", rebuilt.getQuery());
    }
}
