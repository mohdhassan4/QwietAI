package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;

/**
 * Utility class to validate URLs against Server-Side Request Forgery (SSRF) attacks. Rejects URLs
 * that target internal/private network addresses.
 */
public final class UrlSsrfValidator {

    private UrlSsrfValidator() {}

    /**
     * Validates that a URL is safe from SSRF by checking:
     *
     * <ol>
     *   <li>Scheme is http or https only
     *   <li>Hostname does not resolve to any internal/private IP address
     * </ol>
     *
     * @param url the URL to validate
     * @return true if the URL targets a public (non-internal) address, false otherwise
     */
    public static boolean isSafeFromSsrf(URL url) {
        String scheme = url.getProtocol();
        if (scheme == null
                || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
            return false;
        }

        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            return false;
        }

        // Strip brackets from IPv6 literal addresses
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }

        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isInternalAddress(address)) {
                    return false;
                }
            }
            return true;
        } catch (UnknownHostException e) {
            // Fail closed: if we cannot resolve the host, reject it
            return false;
        }
    }

    private static boolean isInternalAddress(InetAddress address) {
        if (address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()) {
            return true;
        }

        // Handle IPv4-mapped IPv6 addresses (::ffff:x.x.x.x) that may not be
        // detected by the standard InetAddress checks on Inet6Address instances
        byte[] bytes = address.getAddress();
        if (bytes.length == 16) {
            boolean isIpv4Mapped = true;
            for (int i = 0; i < 10; i++) {
                if (bytes[i] != 0) {
                    isIpv4Mapped = false;
                    break;
                }
            }
            if (isIpv4Mapped && bytes[10] == (byte) 0xff && bytes[11] == (byte) 0xff) {
                byte[] ipv4Bytes = new byte[4];
                System.arraycopy(bytes, 12, ipv4Bytes, 0, 4);
                try {
                    InetAddress ipv4Address = InetAddress.getByAddress(ipv4Bytes);
                    return ipv4Address.isLoopbackAddress()
                            || ipv4Address.isSiteLocalAddress()
                            || ipv4Address.isLinkLocalAddress()
                            || ipv4Address.isAnyLocalAddress()
                            || ipv4Address.isMulticastAddress();
                } catch (UnknownHostException e) {
                    return true; // Fail closed
                }
            }
        }

        return false;
    }
}
