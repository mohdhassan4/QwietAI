package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class that validates URLs to prevent Server-Side Request Forgery (SSRF) attacks. Ensures
 * that user-supplied URLs do not target internal/private network addresses or use dangerous
 * protocols.
 */
public final class UrlSsrfValidator {

    private UrlSsrfValidator() {}

    /**
     * Validates that the given URL string is safe from SSRF attacks.
     *
     * <p>Checks that:
     *
     * <ul>
     *   <li>The scheme is http or https (blocks file://, ftp://, etc.)
     *   <li>The resolved host IP is not in a private/internal/link-local range
     * </ul>
     *
     * @param urlString the URL to validate
     * @return true if the URL targets a public host via http/https, false otherwise
     */
    public static boolean isSafeUrl(String urlString) {
        if (urlString == null || urlString.isEmpty()) {
            return false;
        }
        try {
            URL url = new URL(urlString);
            String scheme = url.getProtocol();
            if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
                return false;
            }
            String host = url.getHost();
            if (host == null || host.isEmpty()) {
                return false;
            }
            // Strip brackets from IPv6 addresses (URL.getHost() returns [::1] for IPv6)
            if (host.startsWith("[") && host.endsWith("]")) {
                host = host.substring(1, host.length() - 1);
            }
            // Resolve host to IP addresses and check each one
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress addr : addresses) {
                if (isPrivateOrReserved(addr)) {
                    return false;
                }
            }
            return true;
        } catch (MalformedURLException | UnknownHostException e) {
            // Fail closed: if we cannot parse or resolve, reject the URL
            return false;
        }
    }

    private static boolean isPrivateOrReserved(InetAddress addr) {
        return addr.isLoopbackAddress() // 127.0.0.0/8, ::1
                || addr.isSiteLocalAddress() // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
                || addr.isLinkLocalAddress() // 169.254.0.0/16, fe80::/10
                || addr.isAnyLocalAddress() // 0.0.0.0, ::
                || addr.isMulticastAddress() // 224.0.0.0/4
                || isMetadataRange(addr); // additional cloud metadata range check
    }

    /**
     * Additional check for IPv4-mapped IPv6 addresses in the 169.254.0.0/16 range and other cloud
     * metadata endpoint addresses that may not be caught by the standard Java checks.
     */
    private static boolean isMetadataRange(InetAddress addr) {
        byte[] bytes = addr.getAddress();
        if (bytes.length == 4) {
            // IPv4: check 169.254.0.0/16 (link-local / cloud metadata)
            return (bytes[0] & 0xFF) == 169 && (bytes[1] & 0xFF) == 254;
        }
        if (bytes.length == 16) {
            // IPv6: check for IPv4-mapped addresses (::ffff:x.x.x.x)
            // where the embedded IPv4 is in a private/metadata range
            boolean isMapped = true;
            for (int i = 0; i < 10; i++) {
                if (bytes[i] != 0) {
                    isMapped = false;
                    break;
                }
            }
            if (isMapped && (bytes[10] & 0xFF) == 0xFF && (bytes[11] & 0xFF) == 0xFF) {
                int b12 = bytes[12] & 0xFF;
                int b13 = bytes[13] & 0xFF;
                // 169.254.0.0/16
                if (b12 == 169 && b13 == 254) {
                    return true;
                }
                // 127.0.0.0/8
                if (b12 == 127) {
                    return true;
                }
                // 10.0.0.0/8
                if (b12 == 10) {
                    return true;
                }
                // 172.16.0.0/12
                if (b12 == 172 && b13 >= 16 && b13 <= 31) {
                    return true;
                }
                // 192.168.0.0/16
                if (b12 == 192 && b13 == 168) {
                    return true;
                }
            }
        }
        return false;
    }
}
