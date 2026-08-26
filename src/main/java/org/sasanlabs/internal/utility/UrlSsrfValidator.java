package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Validates URLs to prevent Server-Side Request Forgery (SSRF) attacks. Blocks requests to
 * internal/private IP ranges and restricts allowed schemes.
 *
 * @author security-remediation
 */
public final class UrlSsrfValidator {

    private static final transient Logger LOGGER = LogManager.getLogger(UrlSsrfValidator.class);

    private static final Set<String> ALLOWED_SCHEMES =
            new HashSet<>(Arrays.asList("http", "https"));

    private UrlSsrfValidator() {}

    /**
     * Validates whether the given URL string is safe to fetch (not targeting internal/private
     * networks). Performs DNS resolution and checks the resolved IP against blocked ranges.
     *
     * @param urlString the URL to validate
     * @return true if the URL is safe to request, false otherwise
     */
    public static boolean isSafeUrl(String urlString) {
        if (urlString == null || urlString.isBlank()) {
            return false;
        }

        URL url;
        try {
            url = new URL(urlString);
            url.toURI(); // validate URI syntax as well
        } catch (MalformedURLException | URISyntaxException e) {
            LOGGER.error("URL is not valid: {}", urlString, e);
            return false;
        }

        // Only allow http and https schemes
        String scheme = url.getProtocol().toLowerCase();
        if (!ALLOWED_SCHEMES.contains(scheme)) {
            LOGGER.warn("Blocked URL with disallowed scheme: {}", scheme);
            return false;
        }

        String host = url.getHost();
        if (host == null || host.isBlank()) {
            return false;
        }

        // Strip IPv6 brackets if present
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }

        // Resolve hostname to IP addresses and check each one
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isPrivateOrReservedAddress(address)) {
                    LOGGER.warn(
                            "Blocked SSRF attempt to internal/private address: {} resolved to {}",
                            host,
                            address.getHostAddress());
                    return false;
                }
            }
        } catch (UnknownHostException e) {
            LOGGER.error("Cannot resolve hostname: {}", host, e);
            return false;
        }

        return true;
    }

    /**
     * Checks whether the given InetAddress is in a private, reserved, or link-local range.
     *
     * @param address the address to check
     * @return true if the address is private/reserved/internal
     */
    private static boolean isPrivateOrReservedAddress(InetAddress address) {
        // InetAddress built-in checks cover:
        // - isLoopbackAddress: 127.0.0.0/8, ::1
        // - isSiteLocalAddress: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fec0::/10
        // - isLinkLocalAddress: 169.254.0.0/16, fe80::/10
        // - isAnyLocalAddress: 0.0.0.0, ::
        if (address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }

        byte[] addrBytes = address.getAddress();

        // IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) - check the embedded IPv4
        if (addrBytes.length == 16) {
            boolean isIpv4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addrBytes[i] != 0) {
                    isIpv4Mapped = false;
                    break;
                }
            }
            if (isIpv4Mapped
                    && addrBytes[10] == (byte) 0xff
                    && addrBytes[11] == (byte) 0xff) {
                // Extract the IPv4 part and check it
                byte[] ipv4Bytes = new byte[4];
                System.arraycopy(addrBytes, 12, ipv4Bytes, 0, 4);
                try {
                    InetAddress ipv4Address = InetAddress.getByAddress(ipv4Bytes);
                    return isPrivateOrReservedAddress(ipv4Address);
                } catch (UnknownHostException e) {
                    return true; // fail closed
                }
            }

            // IPv6 unique local (fc00::/7)
            if ((addrBytes[0] & 0xfe) == (byte) 0xfc) {
                return true;
            }
        }

        // IPv4: check for 0.0.0.0/8 (current network)
        if (addrBytes.length == 4 && addrBytes[0] == 0) {
            return true;
        }

        return false;
    }
}
