package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.Inet6Address;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class to validate URLs against Server-Side Request Forgery (SSRF) attacks. Ensures that
 * only http/https schemes are used and that the resolved host is not an internal/private address.
 */
public final class UrlSsrfValidator {

    private UrlSsrfValidator() {}

    /**
     * Validates the given URL string against SSRF attacks and returns a parsed URL if safe.
     *
     * @param urlString the URL string to validate
     * @return a validated URL object
     * @throws SecurityException if the URL targets an internal/private address or uses a
     *     disallowed scheme
     * @throws MalformedURLException if the URL string is not a valid URL
     */
    public static URL validateUrl(String urlString) throws MalformedURLException {
        URL url = new URL(urlString);
        String scheme = url.getProtocol();
        if (!"http".equals(scheme) && !"https".equals(scheme)) {
            throw new SecurityException(
                    "Only http and https schemes are allowed, got: " + scheme);
        }

        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            throw new SecurityException("URL host must not be empty");
        }

        // Remove brackets for IPv6 literal addresses
        String resolveHost = host;
        if (resolveHost.startsWith("[") && resolveHost.endsWith("]")) {
            resolveHost = resolveHost.substring(1, resolveHost.length() - 1);
        }

        try {
            InetAddress address = InetAddress.getByName(resolveHost);
            if (isPrivateOrReserved(address)) {
                throw new SecurityException(
                        "Access to internal/private addresses is not allowed: " + host);
            }
        } catch (UnknownHostException e) {
            throw new SecurityException("Cannot resolve host: " + host);
        }

        return url;
    }

    /**
     * Checks whether a URL string is safe from SSRF without throwing exceptions.
     *
     * @param urlString the URL string to validate
     * @return true if the URL is safe, false otherwise
     */
    public static boolean isSafeUrl(String urlString) {
        try {
            validateUrl(urlString);
            return true;
        } catch (MalformedURLException | SecurityException e) {
            return false;
        }
    }

    private static boolean isPrivateOrReserved(InetAddress address) {
        if (address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isAnyLocalAddress()) {
            return true;
        }

        // Handle IPv4-mapped IPv6 addresses (e.g. ::ffff:169.254.169.254)
        if (address instanceof Inet6Address) {
            byte[] bytes = address.getAddress();
            boolean isV4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (bytes[i] != 0) {
                    isV4Mapped = false;
                    break;
                }
            }
            if (isV4Mapped && bytes[10] == (byte) 0xff && bytes[11] == (byte) 0xff) {
                byte[] v4Bytes = new byte[4];
                System.arraycopy(bytes, 12, v4Bytes, 0, 4);
                try {
                    InetAddress v4Address = InetAddress.getByAddress(v4Bytes);
                    return isPrivateOrReserved(v4Address);
                } catch (UnknownHostException e) {
                    return true; // fail closed
                }
            }
            // Check for IPv6 unique-local addresses (fc00::/7)
            int firstByte = bytes[0] & 0xFF;
            if ((firstByte & 0xFE) == 0xFC) {
                return true;
            }
        }

        // Explicit IPv4 range checks as defense-in-depth
        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            int first = bytes[0] & 0xFF;
            int second = bytes[1] & 0xFF;
            // 127.0.0.0/8 (loopback)
            if (first == 127) return true;
            // 10.0.0.0/8 (private)
            if (first == 10) return true;
            // 172.16.0.0/12 (private)
            if (first == 172 && second >= 16 && second <= 31) return true;
            // 192.168.0.0/16 (private)
            if (first == 192 && second == 168) return true;
            // 169.254.0.0/16 (link-local)
            if (first == 169 && second == 254) return true;
            // 0.0.0.0/8
            if (first == 0) return true;
        }

        return false;
    }
}
