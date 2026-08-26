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
 * Utility class providing SSRF protection by validating URLs against internal/private IP ranges and
 * restricting allowed schemes.
 */
public final class SsrfProtectionUtil {

    private static final transient Logger LOGGER = LogManager.getLogger(SsrfProtectionUtil.class);

    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    private SsrfProtectionUtil() {}

    /**
     * Validates that a URL is safe from SSRF attacks. Checks that the scheme is http/https, the
     * URL is well-formed, and the resolved IP address is not in a private/internal range.
     *
     * @param urlString the URL string to validate
     * @return true if the URL is safe to request, false otherwise
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
            LOGGER.error("URL validation failed for: {}", urlString, e);
            return false;
        }

        String scheme = url.getProtocol().toLowerCase();
        if (!ALLOWED_SCHEMES.contains(scheme)) {
            LOGGER.warn("Blocked URL with disallowed scheme: {}", scheme);
            return false;
        }

        String host = url.getHost();
        if (host == null || host.isBlank()) {
            return false;
        }

        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isPrivateOrReservedAddress(address)) {
                    LOGGER.warn(
                            "Blocked SSRF attempt to private/reserved IP: {}", address.getHostAddress());
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
     * Checks if an IP address is in a private, loopback, link-local, or other reserved range.
     *
     * @param address the InetAddress to check
     * @return true if the address is private/reserved, false otherwise
     */
    private static boolean isPrivateOrReservedAddress(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()
                || isCloudMetadataAddress(address);
    }

    /**
     * Checks if an address is a known cloud metadata endpoint (169.254.169.254, 169.254.170.2).
     */
    private static boolean isCloudMetadataAddress(InetAddress address) {
        byte[] addr = address.getAddress();
        if (addr.length == 4) {
            // 169.254.169.254 and 169.254.170.2 (AWS metadata endpoints)
            int first = addr[0] & 0xFF;
            int second = addr[1] & 0xFF;
            if (first == 169 && second == 254) {
                return true;
            }
        }
        if (addr.length == 16) {
            // IPv6-mapped IPv4: check last 4 bytes for 169.254.x.x
            boolean isV4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addr[i] != 0) {
                    isV4Mapped = false;
                    break;
                }
            }
            if (isV4Mapped && (addr[10] & 0xFF) == 0xFF && (addr[11] & 0xFF) == 0xFF) {
                int first = addr[12] & 0xFF;
                int second = addr[13] & 0xFF;
                if (first == 169 && second == 254) {
                    return true;
                }
            }
        }
        return false;
    }
}
