package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Locale;

/**
 * Validates URL hosts to prevent SSRF attacks by rejecting private/internal IP ranges and
 * restricting allowed schemes to http and https.
 */
public final class UrlHostValidator {

    private UrlHostValidator() {}

    /**
     * Returns true if the given URL string has an allowed scheme (http/https) and its host does not
     * resolve to a private or internal IP address.
     *
     * @param urlString the URL string to validate
     * @return true if the URL is safe to fetch, false otherwise
     */
    public static boolean isSafeUrl(String urlString) {
        if (urlString == null || urlString.isBlank()) {
            return false;
        }
        try {
            URL url = new URL(urlString);
            return isSafeUrl(url);
        } catch (MalformedURLException e) {
            return false;
        }
    }

    /**
     * Returns true if the given URL has an allowed scheme (http/https) and its host does not
     * resolve to a private or internal IP address.
     *
     * @param url the URL to validate
     * @return true if the URL is safe to fetch, false otherwise
     */
    public static boolean isSafeUrl(URL url) {
        if (url == null) {
            return false;
        }

        String scheme = url.getProtocol();
        if (scheme == null) {
            return false;
        }
        scheme = scheme.toLowerCase(Locale.ROOT);
        if (!("http".equals(scheme) || "https".equals(scheme))) {
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
                    return false;
                }
            }
        } catch (UnknownHostException e) {
            // Cannot resolve host - reject to be safe
            return false;
        }

        return true;
    }

    private static boolean isPrivateOrReserved(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()
                || isCarrierGradeNat(address)
                || isIpv4Mapped169254(address);
    }

    /** Checks for 100.64.0.0/10 (Carrier-Grade NAT). */
    private static boolean isCarrierGradeNat(InetAddress address) {
        byte[] addr = address.getAddress();
        if (addr.length == 4) {
            int first = addr[0] & 0xFF;
            int second = addr[1] & 0xFF;
            return first == 100 && second >= 64 && second <= 127;
        }
        return false;
    }

    /**
     * Additional check for IPv4-mapped IPv6 addresses in the 169.254.0.0/16 range that
     * InetAddress.isLinkLocalAddress may not catch (e.g. [::ffff:169.254.169.254]).
     */
    private static boolean isIpv4Mapped169254(InetAddress address) {
        byte[] addr = address.getAddress();
        if (addr.length == 16) {
            // Check if it's an IPv4-mapped IPv6 address (::ffff:x.x.x.x)
            boolean isV4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addr[i] != 0) {
                    isV4Mapped = false;
                    break;
                }
            }
            if (isV4Mapped && (addr[10] & 0xFF) == 0xFF && (addr[11] & 0xFF) == 0xFF) {
                int third = addr[12] & 0xFF;
                int fourth = addr[13] & 0xFF;
                // 169.254.0.0/16
                if (third == 169 && fourth == 254) {
                    return true;
                }
                // 127.0.0.0/8
                if (third == 127) {
                    return true;
                }
                // 10.0.0.0/8
                if (third == 10) {
                    return true;
                }
                // 172.16.0.0/12
                if (third == 172 && fourth >= 16 && fourth <= 31) {
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
