package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Optional;
import java.util.regex.Pattern;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility class that validates URLs to prevent Server-Side Request Forgery (SSRF) attacks. Ensures
 * that only http/https schemes are used and that the resolved host is not an internal, loopback, or
 * link-local address.
 */
public final class UrlSafetyValidator {

    private static final transient Logger LOGGER = LogManager.getLogger(UrlSafetyValidator.class);

    /**
     * Pattern for a valid hostname: labels separated by dots, each label starts/ends with
     * alphanumeric, may contain hyphens internally.
     */
    private static final Pattern VALID_HOSTNAME_PATTERN =
            Pattern.compile(
                    "^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)*"
                            + "[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?$");

    /** Pattern to detect IPv4 address literals. */
    private static final Pattern IPV4_PATTERN =
            Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");

    private UrlSafetyValidator() {}

    /**
     * Validates the given URL string against SSRF attacks and returns the validated URL object. The
     * returned URL is safe to use for connections. Returning the URL object (rather than just a
     * boolean) breaks the taint chain from the original user-controlled string.
     *
     * @param urlString the URL to validate
     * @return an Optional containing the validated URL if safe, or empty if unsafe
     */
    public static Optional<URL> getValidatedUrl(String urlString) {
        try {
            URL url = new URL(urlString);
            url.toURI();

            // Only allow http and https schemes
            String protocol = url.getProtocol().toLowerCase();
            if (!"http".equals(protocol) && !"https".equals(protocol)) {
                LOGGER.warn(
                        "Blocked URL with disallowed scheme: {}",
                        LogSanitizer.sanitize(protocol));
                return Optional.empty();
            }

            // Resolve the hostname to an IP address and check it is not internal
            String host = url.getHost();
            if (host == null || host.isEmpty()) {
                LOGGER.warn("Blocked URL with empty host");
                return Optional.empty();
            }

            // Strip IPv6 brackets if present for validation
            String rawHost = host;
            if (rawHost.startsWith("[") && rawHost.endsWith("]")) {
                rawHost = rawHost.substring(1, rawHost.length() - 1);
            }

            // Validate hostname format before any network operation
            if (!isValidHostFormat(rawHost)) {
                LOGGER.warn(
                        "Blocked URL with invalid host format: {}",
                        LogSanitizer.sanitize(rawHost));
                return Optional.empty();
            }

            // Check if the host is an IP literal that resolves to an internal address
            if (isIpLiteral(rawHost)) {
                InetAddress literalAddr = InetAddress.getByName(rawHost);
                if (isInternalAddress(literalAddr)) {
                    LOGGER.warn(
                            "Blocked URL with internal IP literal: {}",
                            LogSanitizer.sanitize(rawHost));
                    return Optional.empty();
                }
            }

            // Resolve the hostname via DNS and verify all addresses are public
            InetAddress[] addresses = InetAddress.getAllByName(rawHost);
            for (InetAddress address : addresses) {
                if (isInternalAddress(address)) {
                    LOGGER.warn(
                            "Blocked URL resolving to internal address: {} -> {}",
                            LogSanitizer.sanitize(rawHost),
                            address.getHostAddress());
                    return Optional.empty();
                }
            }

            return Optional.of(url);
        } catch (MalformedURLException | URISyntaxException e) {
            LOGGER.error(
                    "URL validation failed - malformed URL: {}",
                    LogSanitizer.sanitize(urlString),
                    e);
            return Optional.empty();
        } catch (UnknownHostException e) {
            LOGGER.error(
                    "URL validation failed - cannot resolve host: {}",
                    LogSanitizer.sanitize(urlString),
                    e);
            return Optional.empty();
        }
    }

    /**
     * Validates the given URL string against SSRF attacks.
     *
     * @param urlString the URL to validate
     * @return true if the URL is safe to fetch (public http/https), false otherwise
     */
    public static boolean isSafeUrl(String urlString) {
        return getValidatedUrl(urlString).isPresent();
    }

    /**
     * Validates that the host string has a valid format (either a valid hostname or a valid IP
     * literal). Rejects suspicious patterns before any network operation.
     */
    private static boolean isValidHostFormat(String host) {
        if (host == null || host.isEmpty()) {
            return false;
        }
        // Allow valid IPv4 literals
        if (IPV4_PATTERN.matcher(host).matches()) {
            return true;
        }
        // Allow IPv6 (already stripped of brackets)
        if (host.contains(":")) {
            return true;
        }
        // Must match a valid hostname pattern
        return VALID_HOSTNAME_PATTERN.matcher(host).matches();
    }

    /** Checks if the host string is an IP address literal (IPv4 or IPv6). */
    private static boolean isIpLiteral(String host) {
        // IPv4 literal
        if (IPV4_PATTERN.matcher(host).matches()) {
            return true;
        }
        // IPv6 literal (contains colons)
        return host.contains(":");
    }

    /**
     * Checks whether an InetAddress is an internal/private/loopback/link-local address.
     *
     * @param address the address to check
     * @return true if the address is internal and should be blocked
     */
    static boolean isInternalAddress(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isAnyLocalAddress()
                || isCarrierGradeNat(address)
                || isIpv4Mapped169254(address);
    }

    /** Checks for 100.64.0.0/10 (Carrier-Grade NAT / shared address space). */
    private static boolean isCarrierGradeNat(InetAddress address) {
        byte[] addr = address.getAddress();
        if (addr.length == 4) {
            int first = addr[0] & 0xFF;
            int second = addr[1] & 0xFF;
            // 100.64.0.0/10: first byte 100, second byte 64-127
            return first == 100 && (second >= 64 && second <= 127);
        }
        return false;
    }

    /**
     * Detects IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) that map to link-local 169.254.0.0/16.
     */
    private static boolean isIpv4Mapped169254(InetAddress address) {
        byte[] addr = address.getAddress();
        if (addr.length == 16) {
            // Check for IPv4-mapped IPv6: first 10 bytes zero, bytes 10-11 are 0xFF
            boolean isIpv4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addr[i] != 0) {
                    isIpv4Mapped = false;
                    break;
                }
            }
            if (isIpv4Mapped && (addr[10] & 0xFF) == 0xFF && (addr[11] & 0xFF) == 0xFF) {
                int third = addr[12] & 0xFF;
                int fourth = addr[13] & 0xFF;
                // 169.254.0.0/16
                if (third == 169 && fourth == 254) {
                    return true;
                }
                // Also check other private ranges in mapped form
                // 10.0.0.0/8
                if (third == 10) {
                    return true;
                }
                // 127.0.0.0/8
                if (third == 127) {
                    return true;
                }
                // 172.16.0.0/12
                if (third == 172 && (fourth >= 16 && fourth <= 31)) {
                    return true;
                }
                // 192.168.0.0/16
                if (third == 192 && fourth == 168) {
                    return true;
                }
            }
        }
        return false;
    }
}
