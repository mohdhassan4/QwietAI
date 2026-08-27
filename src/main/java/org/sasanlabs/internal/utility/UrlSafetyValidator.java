package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility class to validate that a URL does not target internal/private network addresses,
 * preventing Server-Side Request Forgery (SSRF) attacks.
 */
public final class UrlSafetyValidator {

    private static final transient Logger LOGGER = LogManager.getLogger(UrlSafetyValidator.class);

    private UrlSafetyValidator() {}

    /**
     * Checks whether the given URL targets a safe (non-internal, non-private) destination. Blocks
     * file:// protocol and URLs resolving to private/reserved IP ranges: 127.0.0.0/8, 10.0.0.0/8,
     * 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, ::1, fd00::/8, fe80::/10, and other
     * reserved/multicast ranges.
     *
     * @param urlString the URL string to validate
     * @return true if the URL targets a public/external address, false otherwise
     */
    public static boolean isSafeUrl(String urlString) {
        if (urlString == null || urlString.isBlank()) {
            return false;
        }

        URL url;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            LOGGER.error("Malformed URL: {}", LogSanitizer.sanitize(urlString), e);
            return false;
        }

        String protocol = url.getProtocol();
        if (protocol == null || (!protocol.equals("http") && !protocol.equals("https"))) {
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

        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isPrivateOrReserved(address)) {
                    LOGGER.warn(
                            "URL {} resolves to private/reserved address: {}",
                            LogSanitizer.sanitize(urlString),
                            address.getHostAddress());
                    return false;
                }
            }
        } catch (UnknownHostException e) {
            LOGGER.error("Cannot resolve host for URL: {}", LogSanitizer.sanitize(urlString), e);
            return false;
        }

        return true;
    }

    /**
     * Determines if an InetAddress is in a private or reserved range.
     *
     * @param address the address to check
     * @return true if the address is private/reserved/loopback/link-local
     */
    static boolean isPrivateOrReserved(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()
                || isCarrierGradeNat(address)
                || isUniqueLocalAddress(address);
    }

    /** Checks for 100.64.0.0/10 (Carrier-grade NAT / Shared Address Space). */
    private static boolean isCarrierGradeNat(InetAddress address) {
        byte[] addr = address.getAddress();
        if (addr.length == 4) {
            int first = addr[0] & 0xFF;
            int second = addr[1] & 0xFF;
            return first == 100 && (second >= 64 && second <= 127);
        }
        return false;
    }

    /** Checks for IPv6 Unique Local Addresses (fd00::/8). */
    private static boolean isUniqueLocalAddress(InetAddress address) {
        byte[] addr = address.getAddress();
        if (addr.length == 16) {
            int first = addr[0] & 0xFF;
            return first == 0xFD || first == 0xFC;
        }
        return false;
    }
}
