package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Utility to validate URL hosts for SSRF protection. Rejects internal, loopback, link-local,
 * metadata service, and private network addresses.
 */
public final class UrlHostValidator {

    private static final Set<String> BLOCKED_HOSTNAMES =
            new HashSet<>(
                    Arrays.asList(
                            "metadata.google.internal",
                            "metadata.goog",
                            "localhost"));

    private static final Set<String> ALLOWED_SCHEMES =
            new HashSet<>(Arrays.asList("http", "https"));

    private UrlHostValidator() {}

    /**
     * Returns true if the URL host is safe to connect to (not internal/loopback/link-local/metadata
     * service/private network).
     *
     * @param url the URL to validate
     * @return true if the host resolves to a public, non-blocked address
     */
    public static boolean isHostSafe(URL url) {
        String scheme = url.getProtocol();
        if (scheme == null || !ALLOWED_SCHEMES.contains(scheme.toLowerCase())) {
            return false;
        }

        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            return false;
        }

        // Strip IPv6 brackets if present
        if (host.startsWith("[") && host.endsWith("]")) {
            host = host.substring(1, host.length() - 1);
        }

        String hostLower = host.toLowerCase();
        if (BLOCKED_HOSTNAMES.contains(hostLower)) {
            return false;
        }

        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                if (isBlockedAddress(address)) {
                    return false;
                }
            }
            return true;
        } catch (UnknownHostException e) {
            // Cannot resolve hostname - block to be safe
            return false;
        }
    }

    private static boolean isBlockedAddress(InetAddress address) {
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
            // Block 169.254.0.0/16 explicitly (link-local / cloud metadata)
            return (addr[0] & 0xFF) == 169 && (addr[1] & 0xFF) == 254;
        }
        if (addr.length == 16) {
            // Check for IPv4-mapped IPv6 ::ffff:169.254.x.x
            boolean isMappedV4 = true;
            for (int i = 0; i < 10; i++) {
                if (addr[i] != 0) {
                    isMappedV4 = false;
                    break;
                }
            }
            if (isMappedV4
                    && (addr[10] & 0xFF) == 0xFF
                    && (addr[11] & 0xFF) == 0xFF) {
                return (addr[12] & 0xFF) == 169 && (addr[13] & 0xFF) == 254;
            }
        }
        return false;
    }
}
