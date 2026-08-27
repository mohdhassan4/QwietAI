package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility class providing SSRF (Server-Side Request Forgery) protection by validating URLs against
 * private/internal IP ranges before allowing outbound requests.
 */
public final class SsrfProtectionUtils {

    private static final transient Logger LOGGER = LogManager.getLogger(SsrfProtectionUtils.class);

    private SsrfProtectionUtils() {}

    /**
     * Validates whether a URL is safe from SSRF attacks. Rejects URLs whose resolved host falls
     * into private, loopback, link-local, or metadata IP ranges.
     *
     * @param urlString the URL to validate
     * @return true if the URL is safe to fetch, false otherwise
     */
    public static boolean isSafeUrl(String urlString) {
        try {
            URL url = new URL(urlString);
            String protocol = url.getProtocol();
            if (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol)) {
                LOGGER.warn("SSRF protection: rejected non-HTTP protocol: {}", protocol);
                return false;
            }

            String host = url.getHost();
            if (host == null || host.isEmpty()) {
                LOGGER.warn("SSRF protection: rejected URL with empty host");
                return false;
            }

            // Strip brackets from IPv6 literal hosts
            if (host.startsWith("[") && host.endsWith("]")) {
                host = host.substring(1, host.length() - 1);
            }

            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isPrivateOrReserved(address)) {
                    LOGGER.warn(
                            "SSRF protection: rejected URL resolving to private/internal address:"
                                    + " {}",
                            address.getHostAddress());
                    return false;
                }
            }
            return true;
        } catch (MalformedURLException e) {
            LOGGER.error("SSRF protection: malformed URL: {}", urlString, e);
            return false;
        } catch (UnknownHostException e) {
            LOGGER.error("SSRF protection: unable to resolve host for URL: {}", urlString, e);
            return false;
        }
    }

    /**
     * Checks whether an InetAddress is in a private, loopback, link-local, or otherwise reserved
     * range that should not be accessed via SSRF-vulnerable endpoints.
     */
    private static boolean isPrivateOrReserved(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isAnyLocalAddress()
                || isMetadataAddress(address);
    }

    /**
     * Checks for cloud metadata service addresses (169.254.169.254, fd00::/8 ULA range).
     */
    private static boolean isMetadataAddress(InetAddress address) {
        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            // 169.254.169.254 (AWS/GCP/Azure metadata)
            int b0 = bytes[0] & 0xFF;
            int b1 = bytes[1] & 0xFF;
            int b2 = bytes[2] & 0xFF;
            int b3 = bytes[3] & 0xFF;
            if (b0 == 169 && b1 == 254 && b2 == 169 && b3 == 254) {
                return true;
            }
        } else if (bytes.length == 16) {
            // fd00::/8 (Unique Local Address)
            int firstByte = bytes[0] & 0xFF;
            if (firstByte == 0xFD) {
                return true;
            }
            // IPv4-mapped IPv6 (::ffff:a.b.c.d) — extract the IPv4 portion and re-check
            if (isIpv4MappedIpv6(bytes)) {
                int b0 = bytes[12] & 0xFF;
                int b1 = bytes[13] & 0xFF;
                int b2 = bytes[14] & 0xFF;
                int b3 = bytes[15] & 0xFF;
                if (b0 == 169 && b1 == 254 && b2 == 169 && b3 == 254) {
                    return true;
                }
                // Also check private ranges in mapped form
                if (b0 == 10) return true;
                if (b0 == 172 && (b1 >= 16 && b1 <= 31)) return true;
                if (b0 == 192 && b1 == 168) return true;
                if (b0 == 127) return true;
            }
        }
        return false;
    }

    private static boolean isIpv4MappedIpv6(byte[] bytes) {
        // ::ffff:0:0/96 prefix
        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) return false;
        }
        return (bytes[10] & 0xFF) == 0xFF && (bytes[11] & 0xFF) == 0xFF;
    }
}
