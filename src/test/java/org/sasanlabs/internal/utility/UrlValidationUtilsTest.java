package org.sasanlabs.internal.utility;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Set;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class UrlValidationUtilsTest {

    /**
     * Contains, on purpose, internal hosts so that the address based validation is exercised even
     * when a host is allow listed, eg because of a stale allow list entry.
     */
    private static final Set<String> ALLOWED_HOSTS =
            Set.of(
                    "gist.githubusercontent.com",
                    "8.8.8.8",
                    "localhost",
                    "127.0.0.1",
                    "169.254.169.254",
                    "[::ffff:169.254.169.254]",
                    "[::1]",
                    "[fd00::1]",
                    "10.0.0.1",
                    "172.16.0.1",
                    "192.168.0.1",
                    "100.64.0.1",
                    "0.0.0.0");

    @ParameterizedTest
    @ValueSource(
            strings = {
                "http://localhost/latest/meta-data",
                "http://127.0.0.1/latest/meta-data",
                "http://169.254.169.254/latest/meta-data",
                "http://[::ffff:169.254.169.254]/latest/meta-data",
                "http://[::1]/latest/meta-data",
                "http://[fd00::1]/latest/meta-data",
                "http://10.0.0.1/latest/meta-data",
                "http://172.16.0.1/latest/meta-data",
                "http://192.168.0.1/latest/meta-data",
                "http://100.64.0.1/latest/meta-data",
                "http://0.0.0.0/latest/meta-data"
            })
    void internalAddressesAreRejected(String url) throws MalformedURLException {
        assertFalse(UrlValidationUtils.isAllowedDestination(new URL(url), ALLOWED_HOSTS));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "file:///etc/passwd",
                "ftp://gist.githubusercontent.com/raw/projects",
                "jar:file:///tmp/archive.jar!/entry"
            })
    void nonHttpSchemesAreRejected(String url) throws MalformedURLException {
        assertFalse(UrlValidationUtils.isAllowedDestination(new URL(url), ALLOWED_HOSTS));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "https://user:password@gist.githubusercontent.com/raw/projects",
                "https://gist.githubusercontent.com@169.254.169.254/latest/meta-data"
            })
    void urlsCarryingCredentialsAreRejected(String url) throws MalformedURLException {
        assertFalse(UrlValidationUtils.isAllowedDestination(new URL(url), ALLOWED_HOSTS));
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "https://evil.example.com/payload",
                "https://gist.githubusercontent.com.evil.example.com/raw/projects",
                "http://1.1.1.1/payload"
            })
    void hostsWhichAreNotAllowListedAreRejected(String url) throws MalformedURLException {
        assertFalse(UrlValidationUtils.isAllowedDestination(new URL(url), ALLOWED_HOSTS));
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://8.8.8.8/payload", "https://8.8.8.8/payload"})
    void allowListedPublicDestinationsAreAccepted(String url) throws MalformedURLException {
        assertTrue(UrlValidationUtils.isAllowedDestination(new URL(url), ALLOWED_HOSTS));
    }
}
