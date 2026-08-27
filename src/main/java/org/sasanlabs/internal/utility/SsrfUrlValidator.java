package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class to validate URLs against Server-Side Request Forgery (SSRF) attacks. Blocks
 * requests to internal/private IP ranges and restricts URL schemes to http and https.
 */
public final class SsrfUrlValidator {

    private SsrfUrlValidator() {}

    /**
     * Validates the given URL string against SSRF attacks and returns a safe URL object. This
     * method acts as a sanitizer boundary: the returned URL is guaranteed to target a public
     * external host via http or https.
     *
     * @param urlString the URL string to validate
     * @return a validated URL object safe from SSRF
     * @throws SecurityException if the URL is unsafe (internal IP, non-http(s) scheme, or invalid)
     */
    public static URL validateUrl(String urlString) {
        URL validated = validateInternal(urlString);
        if (validated == null) {
            throw new SecurityException("URL blocked by SSRF protection");
        }
        return validated;
    }

    /**
     * Validates that the given URL is safe from SSRF attacks by checking scheme and resolved IP
     * addresses.
     *
     * @param urlString the URL string to validate
     * @return true if the URL targets a public external host via http/https, false otherwise
     */
    public static boolean isSafeFromSsrf(String urlString) {
        return validateInternal(urlString) != null;
    }

    private static URL validateInternal(String urlString) {
        URI uri;
        try {
            uri = new URI(urlString);
        } catch (URISyntaxException e) {
            return null;
        }
        String scheme = uri.getScheme();
        if (scheme == null) {
            return null;
        }
        scheme = scheme.toLowerCase();
        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            return null;
        }
        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            return null;
        }
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isInternalAddress(address)) {
                    return null;
                }
            }
        } catch (UnknownHostException e) {
            return null;
        }
        try {
            return uri.toURL();
        } catch (MalformedURLException e) {
            return null;
        }
    }

    private static boolean isInternalAddress(InetAddress address) {
        if (address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isAnyLocalAddress()) {
            return true;
        }
        byte[] bytes = address.getAddress();
        if (bytes.length == 16) {
            // Check fd00::/8 (Unique Local Address, not covered by isSiteLocalAddress)
            if ((bytes[0] & 0xFF) == 0xFD) {
                return true;
            }
            // Check IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
            if (isIPv4MappedIPv6(bytes)) {
                byte[] ipv4Bytes = new byte[4];
                System.arraycopy(bytes, 12, ipv4Bytes, 0, 4);
                try {
                    InetAddress ipv4Address = InetAddress.getByAddress(ipv4Bytes);
                    return ipv4Address.isLoopbackAddress()
                            || ipv4Address.isSiteLocalAddress()
                            || ipv4Address.isLinkLocalAddress()
                            || ipv4Address.isAnyLocalAddress();
                } catch (UnknownHostException e) {
                    // Fail closed: treat as internal
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean isIPv4MappedIPv6(byte[] bytes) {
        if (bytes.length != 16) {
            return false;
        }
        for (int i = 0; i < 10; i++) {
            if (bytes[i] != 0) {
                return false;
            }
        }
        return (bytes[10] & 0xFF) == 0xFF && (bytes[11] & 0xFF) == 0xFF;
    }
}
