package org.sasanlabs.internal.utility;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.net.URL;
import java.util.Collections;
import java.util.Set;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;

/** Destination allowlist checks behind the SSRF (CWE-918) remediations. */
class SafeUrlUtilsTest {

    private static final Set<String> ALLOWED_HOSTS =
            SafeUrlUtils.parseAllowedHosts("gist.githubusercontent.com, GitHub.com ,,");

    @Test
    void parseAllowedHosts_normalisesTrimsAndDropsEmptyEntries() {
        assertThat(ALLOWED_HOSTS).containsExactly("gist.githubusercontent.com", "github.com");
        assertThat(SafeUrlUtils.parseAllowedHosts(null)).isEmpty();
        assertThat(SafeUrlUtils.parseAllowedHosts("  ")).isEmpty();
    }

    @Test
    void requireAllowedDestination_acceptsAnAllowlistedHost() {
        URL url =
                SafeUrlUtils.requireAllowedDestination(
                        "https://gist.githubusercontent.com/raw/abc", ALLOWED_HOSTS);

        assertThat(url.getHost()).isEqualTo("gist.githubusercontent.com");
        assertThat(url.getPath()).isEqualTo("/raw/abc");
    }

    @Test
    void requireAllowedDestination_isCaseInsensitiveAboutTheHost() {
        assertThatCode(
                        () ->
                                SafeUrlUtils.requireAllowedDestination(
                                        "https://GitHub.COM/SasanLabs", ALLOWED_HOSTS))
                .doesNotThrowAnyException();
    }

    @Test
    void requireAllowedDestination_refusesHostsOffTheAllowlist() {
        assertRejected(
                () -> SafeUrlUtils.requireAllowedDestination("http://localhost/", ALLOWED_HOSTS));
        assertRejected(
                () -> SafeUrlUtils.requireAllowedDestination("http://127.0.0.1/", ALLOWED_HOSTS));
        assertRejected(
                () -> SafeUrlUtils.requireAllowedDestination("http://10.1.2.3/", ALLOWED_HOSTS));
        assertRejected(
                () ->
                        SafeUrlUtils.requireAllowedDestination(
                                "http://169.254.169.254/latest/meta-data", ALLOWED_HOSTS));
        assertRejected(
                () ->
                        SafeUrlUtils.requireAllowedDestination(
                                "http://[::ffff:169.254.169.254]/1.0", ALLOWED_HOSTS));
        assertRejected(
                () ->
                        SafeUrlUtils.requireAllowedDestination(
                                "https://github.com.attacker.test/", ALLOWED_HOSTS));
    }

    @Test
    void requireAllowedDestination_refusesEverythingWhenNothingIsAllowed() {
        assertRejected(
                () ->
                        SafeUrlUtils.requireAllowedDestination(
                                "https://github.com/SasanLabs", Collections.emptySet()));
        assertRejected(
                () -> SafeUrlUtils.requireAllowedDestination("https://github.com/SasanLabs", null));
    }

    @Test
    void requireAllowedDestination_refusesUnusableUrls() {
        assertRejected(() -> SafeUrlUtils.requireAllowedDestination(null, ALLOWED_HOSTS));
        assertRejected(() -> SafeUrlUtils.requireAllowedDestination("   ", ALLOWED_HOSTS));
        assertRejected(() -> SafeUrlUtils.requireAllowedDestination("invalidUrl", ALLOWED_HOSTS));
        assertRejected(
                () ->
                        SafeUrlUtils.requireAllowedDestination(
                                "https://github.com/a b", ALLOWED_HOSTS));
        assertRejected(
                () ->
                        SafeUrlUtils.requireAllowedDestination(
                                "https://github.com/a" + ((char) 0), ALLOWED_HOSTS));
    }

    @Test
    void requireAllowedDestination_refusesSchemesOtherThanHttpAndHttps() {
        assertRejected(
                () -> SafeUrlUtils.requireAllowedDestination("file:///etc/passwd", ALLOWED_HOSTS));
        assertRejected(
                () ->
                        SafeUrlUtils.requireAllowedDestination(
                                "ftp://github.com/secret", ALLOWED_HOSTS));
    }

    @Test
    void requireAllowedDestination_refusesCredentialsInTheUrl() {
        assertRejected(
                () ->
                        SafeUrlUtils.requireAllowedDestination(
                                "https://user:pass@github.com/SasanLabs", ALLOWED_HOSTS));
    }

    @Test
    void requireAllowedAddress_refusesInternalAddresses() throws Exception {
        assertRejected(() -> SafeUrlUtils.requireAllowedAddress(new URL("http://127.0.0.1/")));
        assertRejected(() -> SafeUrlUtils.requireAllowedAddress(new URL("http://10.1.2.3/")));
        assertRejected(() -> SafeUrlUtils.requireAllowedAddress(new URL("http://192.168.0.5/")));
        assertRejected(
                () ->
                        SafeUrlUtils.requireAllowedAddress(
                                new URL("http://169.254.169.254/latest/meta-data")));
        assertRejected(() -> SafeUrlUtils.requireAllowedAddress(new URL("http://[::1]/")));
        assertRejected(() -> SafeUrlUtils.requireAllowedAddress(new URL("http://[fd00::254]/")));
        assertRejected(() -> SafeUrlUtils.requireAllowedAddress(new URL("http://100.64.0.1/")));
        assertRejected(() -> SafeUrlUtils.requireAllowedAddress(null));
    }

    @Test
    void requireAllowedAddress_acceptsAPublicAddress() {
        assertThatCode(() -> SafeUrlUtils.requireAllowedAddress(new URL("http://8.8.8.8/")))
                .doesNotThrowAnyException();
    }

    private static void assertRejected(ThrowingCallable callable) {
        assertThatThrownBy(callable).isInstanceOf(IllegalArgumentException.class);
    }
}
