package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class for URL validation to prevent SSRF attacks. Validates that a URL does not point to
 * internal/private network addresses.
 */
public final class UrlValidationUtils {

    private UrlValidationUtils() {}

    /**
     * Validates that the given URL is safe to request (not targeting internal/private networks).
     *
     * @param url the URL string to validate
     * @return true if the URL is safe to request, false otherwise
     */
    public static boolean isSafeUrl(String url) {
        try {
            URL parsedUrl = new URL(url);
            return isSafeUrl(parsedUrl);
        } catch (MalformedURLException e) {
            return false;
        }
    }

    /**
     * Validates that the given URL is safe to request (not targeting internal/private networks).
     *
     * @param parsedUrl the parsed URL to validate
     * @return true if the URL is safe to request, false otherwise
     */
    public static boolean isSafeUrl(URL parsedUrl) {
        String scheme = parsedUrl.getProtocol();
        if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
            return false;
        }

        String host = parsedUrl.getHost();
        if (host == null || host.isEmpty()) {
            return false;
        }

        // Strip brackets from IPv6 literal addresses for resolution
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }

        // Reject localhost by name
        if (host.equalsIgnoreCase("localhost")) {
            return false;
        }

        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isPrivateOrReservedAddress(address)) {
                    return false;
                }
            }
        } catch (UnknownHostException e) {
            // If we cannot resolve the host, reject it
            return false;
        }

        return true;
    }

    private static boolean isPrivateOrReservedAddress(InetAddress address) {
        if (address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }

        byte[] addr = address.getAddress();

        // Handle IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
        if (addr.length == 16 && isIpv4MappedIpv6(addr)) {
            byte[] ipv4 = new byte[4];
            System.arraycopy(addr, 12, ipv4, 0, 4);
            try {
                InetAddress ipv4Address = InetAddress.getByAddress(ipv4);
                return ipv4Address.isLoopbackAddress()
                        || ipv4Address.isSiteLocalAddress()
                        || ipv4Address.isLinkLocalAddress()
                        || ipv4Address.isAnyLocalAddress()
                        || ipv4Address.isMulticastAddress()
                        || isCloudMetadataIpv4(ipv4);
            } catch (UnknownHostException e) {
                return true;
            }
        }

        if (addr.length == 4) {
            return isCloudMetadataIpv4(addr);
        }

        return false;
    }

    private static boolean isIpv4MappedIpv6(byte[] addr) {
        // ::ffff:x.x.x.x => first 10 bytes zero, bytes 10-11 are 0xFF
        for (int i = 0; i < 10; i++) {
            if (addr[i] != 0) {
                return false;
            }
        }
        return (addr[10] & 0xFF) == 0xFF && (addr[11] & 0xFF) == 0xFF;
    }

    private static boolean isCloudMetadataIpv4(byte[] addr) {
        // 169.254.169.254 - cloud metadata endpoint
        return (addr[0] & 0xFF) == 169
                && (addr[1] & 0xFF) == 254
                && (addr[2] & 0xFF) == 169
                && (addr[3] & 0xFF) == 254;
    }
}
