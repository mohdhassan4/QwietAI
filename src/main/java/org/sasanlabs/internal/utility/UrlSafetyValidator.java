package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility class that validates URLs to prevent Server-Side Request Forgery (SSRF) attacks. Ensures
 * that only http/https schemes are used and that the resolved host is not an internal, loopback, or
 * link-local address.
 */
public final class UrlSafetyValidator {

    private static final transient Logger LOGGER = LogManager.getLogger(UrlSafetyValidator.class);

    private UrlSafetyValidator() {}

    /**
     * Validates the given URL string against SSRF attacks.
     *
     * @param urlString the URL to validate
     * @return true if the URL is safe to fetch (public http/https), false otherwise
     */
    public static boolean isSafeUrl(String urlString) {
        try {
            URL url = new URL(urlString);
            url.toURI();

            // Only allow http and https schemes
            String protocol = url.getProtocol().toLowerCase();
            if (!"http".equals(protocol) && !"https".equals(protocol)) {
                LOGGER.warn("Blocked URL with disallowed scheme: {}", protocol);
                return false;
            }

            // Resolve the hostname to an IP address and check it is not internal
            String host = url.getHost();
            if (host == null || host.isEmpty()) {
                LOGGER.warn("Blocked URL with empty host");
                return false;
            }

            // Strip IPv6 brackets if present
            if (host.startsWith("[") && host.endsWith("]")) {
                host = host.substring(1, host.length() - 1);
            }

            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isInternalAddress(address)) {
                    LOGGER.warn(
                            "Blocked URL resolving to internal address: {} -> {}",
                            host,
                            address.getHostAddress());
                    return false;
                }
            }

            return true;
        } catch (MalformedURLException | URISyntaxException e) {
            LOGGER.error("URL validation failed - malformed URL: {}", urlString, e);
            return false;
        } catch (UnknownHostException e) {
            LOGGER.error("URL validation failed - cannot resolve host: {}", urlString, e);
            return false;
        }
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

    /**
     * Checks for 100.64.0.0/10 (Carrier-Grade NAT / shared address space).
     */
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
