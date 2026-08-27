package org.sasanlabs.internal.utility;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class to validate URLs against Server-Side Request Forgery (SSRF) attacks. Ensures that
 * URLs do not resolve to internal, loopback, or link-local addresses.
 */
public final class UrlValidationUtils {

    private UrlValidationUtils() {}

    /**
     * Validates that the given URL string uses an allowed scheme (http/https) and does not resolve
     * to an internal, loopback, link-local, or metadata IP address.
     *
     * @param urlString the URL string to validate
     * @return the parsed URL if it passes validation
     * @throws IllegalArgumentException if the URL is invalid, uses a disallowed scheme, or resolves
     *     to an internal address
     */
    public static URL validateUrl(String urlString) {
        if (urlString == null || urlString.isBlank()) {
            throw new IllegalArgumentException("URL must not be null or empty");
        }

        URL url;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("Invalid URL: " + e.getMessage(), e);
        }

        String scheme = url.getProtocol();
        if (scheme == null
                || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
            throw new IllegalArgumentException("Only http and https schemes are allowed");
        }

        String host = url.getHost();
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("URL must have a valid host");
        }

        // Strip IPv6 brackets if present for InetAddress resolution
        String hostForResolution = host;
        if (hostForResolution.startsWith("[") && hostForResolution.endsWith("]")) {
            hostForResolution = hostForResolution.substring(1, hostForResolution.length() - 1);
        }

        InetAddress resolvedAddress;
        try {
            resolvedAddress = InetAddress.getByName(hostForResolution);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Cannot resolve host: " + host, e);
        }

        if (isInternalAddress(resolvedAddress)) {
            throw new IllegalArgumentException("Internal URLs not allowed");
        }

        // For IPv4-mapped IPv6 addresses, also check the embedded IPv4 address
        if (resolvedAddress instanceof Inet6Address) {
            byte[] addrBytes = resolvedAddress.getAddress();
            if (isIpv4MappedIpv6(addrBytes)) {
                byte[] ipv4Bytes = new byte[4];
                System.arraycopy(addrBytes, 12, ipv4Bytes, 0, 4);
                try {
                    InetAddress ipv4Address = InetAddress.getByAddress(ipv4Bytes);
                    if (isInternalAddress(ipv4Address)) {
                        throw new IllegalArgumentException("Internal URLs not allowed");
                    }
                } catch (UnknownHostException e) {
                    throw new IllegalArgumentException(
                            "Cannot validate embedded IPv4 address", e);
                }
            }
        }

        return url;
    }

    private static boolean isInternalAddress(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress();
    }

    private static boolean isIpv4MappedIpv6(byte[] addrBytes) {
        if (addrBytes.length != 16) {
            return false;
        }
        // IPv4-mapped IPv6: first 10 bytes zero, bytes 10-11 are 0xff
        for (int i = 0; i < 10; i++) {
            if (addrBytes[i] != 0) {
                return false;
            }
        }
        return addrBytes[10] == (byte) 0xff && addrBytes[11] == (byte) 0xff;
    }
}
