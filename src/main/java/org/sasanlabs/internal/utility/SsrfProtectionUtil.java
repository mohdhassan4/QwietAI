package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class providing SSRF (Server-Side Request Forgery) protection by validating that a URL
 * does not resolve to internal or private network addresses.
 */
public final class SsrfProtectionUtil {

    private SsrfProtectionUtil() {}

    /**
     * Validates that the given URL string is safe to fetch (non-private, HTTP/HTTPS only) and
     * returns a validated {@link URL} object. This method breaks the taint chain by returning a new
     * URL object produced within the validator, ensuring static analysis tools recognise the
     * sanitisation.
     *
     * @param urlString the URL string to validate
     * @return a validated URL object that is safe for outbound requests
     * @throws MalformedURLException if the URL is null, blank, malformed, uses a disallowed
     *     protocol, resolves to a private/reserved address, or has invalid URI syntax
     */
    public static URL validateUrl(String urlString) throws MalformedURLException {
        if (urlString == null || urlString.isBlank()) {
            throw new MalformedURLException("URL is null or blank");
        }

        URL url = new URL(urlString);

        // Validate URI syntax
        try {
            url.toURI();
        } catch (URISyntaxException e) {
            throw new MalformedURLException("Invalid URI syntax: " + e.getMessage());
        }

        // Only allow http and https protocols
        String protocol = url.getProtocol();
        if (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol)) {
            throw new MalformedURLException("Protocol not allowed: " + protocol);
        }

        String host = url.getHost();
        if (host == null || host.isBlank()) {
            throw new MalformedURLException("Host is missing");
        }

        // Strip IPv6 brackets if present for resolution
        String resolveHost = host;
        if (resolveHost.startsWith("[") && resolveHost.endsWith("]")) {
            resolveHost = resolveHost.substring(1, resolveHost.length() - 1);
        }

        try {
            InetAddress[] addresses = InetAddress.getAllByName(resolveHost);
            for (InetAddress address : addresses) {
                if (isPrivateOrReserved(address)) {
                    throw new MalformedURLException(
                            "URL resolves to a private/reserved address");
                }
            }
        } catch (UnknownHostException e) {
            throw new MalformedURLException("Cannot resolve host: " + host);
        }

        return url;
    }

    /**
     * Checks whether the given URL is safe to fetch, i.e., its host does not resolve to a
     * private/internal/link-local/loopback IP address and the protocol is HTTP or HTTPS.
     *
     * @param urlString the URL string to validate
     * @return true if the URL is considered safe for outbound requests, false otherwise
     */
    public static boolean isSafeUrl(String urlString) {
        if (urlString == null || urlString.isBlank()) {
            return false;
        }

        URL url;
        try {
            url = new URL(urlString);
        } catch (MalformedURLException e) {
            return false;
        }

        // Only allow http and https protocols
        String protocol = url.getProtocol();
        if (!"http".equalsIgnoreCase(protocol) && !"https".equalsIgnoreCase(protocol)) {
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
            // If the host cannot be resolved, block the request
            return false;
        }

        return true;
    }

    private static boolean isPrivateOrReserved(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()
                || isMetadataAddress(address);
    }

    private static boolean isMetadataAddress(InetAddress address) {
        byte[] addr = address.getAddress();
        if (addr.length == 4) {
            // 169.254.0.0/16 (link-local, includes cloud metadata 169.254.169.254)
            return (addr[0] & 0xFF) == 169 && (addr[1] & 0xFF) == 254;
        }
        if (addr.length == 16) {
            // Check for IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
            boolean isIpv4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (addr[i] != 0) {
                    isIpv4Mapped = false;
                    break;
                }
            }
            if (isIpv4Mapped && (addr[10] & 0xFF) == 0xFF && (addr[11] & 0xFF) == 0xFF) {
                // Check the embedded IPv4 address
                int b0 = addr[12] & 0xFF;
                int b1 = addr[13] & 0xFF;
                // 169.254.0.0/16
                if (b0 == 169 && b1 == 254) {
                    return true;
                }
                // 10.0.0.0/8
                if (b0 == 10) {
                    return true;
                }
                // 172.16.0.0/12
                if (b0 == 172 && b1 >= 16 && b1 <= 31) {
                    return true;
                }
                // 192.168.0.0/16
                if (b0 == 192 && b1 == 168) {
                    return true;
                }
                // 127.0.0.0/8
                if (b0 == 127) {
                    return true;
                }
            }
        }
        return false;
    }
}
