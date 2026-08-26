package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Validates URLs to prevent Server-Side Request Forgery (SSRF) attacks. Blocks requests to
 * private/internal IP ranges, link-local addresses, cloud metadata endpoints, and non-HTTP
 * schemes.
 *
 * @author SasanLabs
 */
public final class UrlSsrfValidator {

    private static final transient Logger LOGGER = LogManager.getLogger(UrlSsrfValidator.class);

    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    private UrlSsrfValidator() {}

    /**
     * Validates the given URL string is safe from SSRF.
     *
     * @param urlString the URL to validate
     * @return true if the URL is safe to fetch (external, allowed scheme), false otherwise
     */
    public static boolean isSafeUrl(String urlString) {
        if (urlString == null || urlString.isBlank()) {
            return false;
        }

        URL url;
        try {
            url = new URL(urlString);
            url.toURI();
        } catch (MalformedURLException | URISyntaxException e) {
            LOGGER.error(
                    "Provided URL: {} is not valid and following exception occurred",
                    urlString,
                    e);
            return false;
        }

        // Only allow http and https schemes
        String scheme = url.getProtocol();
        if (scheme == null || !ALLOWED_SCHEMES.contains(scheme.toLowerCase())) {
            LOGGER.warn("Blocked URL with disallowed scheme: {}", scheme);
            return false;
        }

        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            return false;
        }

        // Resolve the host to check against private/internal ranges
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isInternalAddress(address)) {
                    LOGGER.warn("Blocked SSRF attempt to internal address: {}", host);
                    return false;
                }
            }
        } catch (UnknownHostException e) {
            LOGGER.error("Cannot resolve host: {}", host, e);
            return false;
        }

        return true;
    }

    /**
     * Checks whether the given InetAddress belongs to a private, loopback, link-local, or other
     * internal network range.
     */
    private static boolean isInternalAddress(InetAddress address) {
        // Loopback (127.0.0.0/8 or ::1)
        if (address.isLoopbackAddress()) {
            return true;
        }

        // Link-local (169.254.0.0/16 or fe80::/10)
        if (address.isLinkLocalAddress()) {
            return true;
        }

        // Site-local / private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or fd00::/8)
        if (address.isSiteLocalAddress()) {
            return true;
        }

        // Any-local / wildcard (0.0.0.0 or ::)
        if (address.isAnyLocalAddress()) {
            return true;
        }

        // Multicast
        if (address.isMulticastAddress()) {
            return true;
        }

        byte[] addrBytes = address.getAddress();

        // IPv4 specific checks
        if (addrBytes.length == 4) {
            // 169.254.0.0/16 (link-local / cloud metadata range)
            if ((addrBytes[0] & 0xFF) == 169 && (addrBytes[1] & 0xFF) == 254) {
                return true;
            }
            // 100.64.0.0/10 (Carrier-Grade NAT)
            if ((addrBytes[0] & 0xFF) == 100
                    && (addrBytes[1] & 0xFF) >= 64
                    && (addrBytes[1] & 0xFF) <= 127) {
                return true;
            }
        }

        // IPv6 specific checks
        if (addrBytes.length == 16) {
            // Unique local address fd00::/8 (already covered by isSiteLocalAddress for fec0,
            // but fd00::/7 covers fc00::/7)
            if ((addrBytes[0] & 0xFE) == 0xFC) {
                return true;
            }
            // IPv4-mapped IPv6 (::ffff:x.x.x.x) - check the embedded IPv4
            if (isIPv4MappedIPv6(addrBytes)) {
                byte[] ipv4Bytes = new byte[4];
                System.arraycopy(addrBytes, 12, ipv4Bytes, 0, 4);
                try {
                    InetAddress ipv4Addr = InetAddress.getByAddress(ipv4Bytes);
                    return isInternalAddress(ipv4Addr);
                } catch (UnknownHostException e) {
                    return true;
                }
            }
        }

        return false;
    }

    /** Checks if the given 16-byte address is an IPv4-mapped IPv6 address (::ffff:x.x.x.x). */
    private static boolean isIPv4MappedIPv6(byte[] addrBytes) {
        if (addrBytes.length != 16) {
            return false;
        }
        for (int i = 0; i < 10; i++) {
            if (addrBytes[i] != 0) {
                return false;
            }
        }
        return (addrBytes[10] & 0xFF) == 0xFF && (addrBytes[11] & 0xFF) == 0xFF;
    }
}
