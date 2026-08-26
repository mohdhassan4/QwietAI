package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class to validate URLs against SSRF attacks. Ensures that only http/https schemes are
 * allowed and that the resolved host IP is not in a private or reserved range.
 */
public final class SsrfProtectionUtil {

    private SsrfProtectionUtil() {}

    /**
     * Validates that a URL is safe to request (not targeting internal/private infrastructure).
     *
     * @param urlString the URL to validate
     * @return true if the URL uses http/https and resolves to a public IP address
     */
    public static boolean isUrlSafeForRequest(String urlString) {
        if (urlString == null || urlString.isEmpty()) {
            return false;
        }
        try {
            URL url = new URL(urlString);
            String protocol = url.getProtocol();
            if (!"http".equals(protocol) && !"https".equals(protocol)) {
                return false;
            }
            String host = url.getHost();
            if (host == null || host.isEmpty()) {
                return false;
            }
            // Remove brackets from IPv6 literal addresses for resolution
            if (host.startsWith("[") && host.endsWith("]")) {
                host = host.substring(1, host.length() - 1);
            }
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isPrivateOrReserved(address)) {
                    return false;
                }
            }
            return true;
        } catch (MalformedURLException | UnknownHostException e) {
            return false;
        }
    }

    private static boolean isPrivateOrReserved(InetAddress address) {
        if (address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }

        byte[] bytes = address.getAddress();
        if (bytes.length == 4) {
            int first = bytes[0] & 0xFF;
            int second = bytes[1] & 0xFF;
            // 0.0.0.0/8
            if (first == 0) {
                return true;
            }
            // 100.64.0.0/10 (Carrier-grade NAT / shared address space)
            if (first == 100 && second >= 64 && second <= 127) {
                return true;
            }
        } else if (bytes.length == 16) {
            // fd00::/8 (IPv6 unique local addresses)
            if ((bytes[0] & 0xFF) == 0xFD) {
                return true;
            }
            // Check IPv4-mapped IPv6 addresses (::ffff:x.x.x.x)
            if (isIPv4MappedIPv6(bytes)) {
                byte[] ipv4 = new byte[4];
                System.arraycopy(bytes, 12, ipv4, 0, 4);
                try {
                    InetAddress ipv4Addr = InetAddress.getByAddress(ipv4);
                    return isPrivateOrReserved(ipv4Addr);
                } catch (UnknownHostException e) {
                    // Fail closed
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
