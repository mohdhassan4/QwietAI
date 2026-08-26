package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Utility class for validating URL hosts against SSRF attacks. Ensures that user-supplied URLs do
 * not target internal, link-local, loopback, or cloud metadata addresses.
 */
public final class UrlHostValidator {

    private static final Set<String> ALLOWED_SCHEMES =
            Collections.unmodifiableSet(new HashSet<>(Arrays.asList("http", "https")));

    private UrlHostValidator() {}

    /**
     * Validates that the given URL targets an allowed external host. Rejects URLs with:
     *
     * <ul>
     *   <li>Non-HTTP(S) schemes (e.g. file://, ftp://)
     *   <li>Loopback addresses (127.x.x.x, ::1)
     *   <li>Private/internal addresses (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
     *   <li>Link-local addresses (169.254.x.x, fe80::)
     *   <li>Any-local/wildcard addresses (0.0.0.0, ::)
     * </ul>
     *
     * @param url the URL to validate
     * @return true if the host is safe to connect to; false otherwise
     */
    public static boolean isHostAllowed(URL url) {
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

        try {
            InetAddress address = InetAddress.getByName(host);
            if (address.isLoopbackAddress()
                    || address.isSiteLocalAddress()
                    || address.isLinkLocalAddress()
                    || address.isAnyLocalAddress()) {
                return false;
            }
            // Check for IPv4-mapped IPv6 link-local (169.254.x.x range)
            byte[] addrBytes = address.getAddress();
            if (addrBytes.length == 4) {
                int first = addrBytes[0] & 0xFF;
                int second = addrBytes[1] & 0xFF;
                if (first == 169 && second == 254) {
                    return false;
                }
            }
            // IPv6: 16-byte address; check for ::ffff:169.254.x.x
            if (addrBytes.length == 16) {
                // Check if it's a mapped IPv4 in the 169.254.x.x range
                boolean isMapped = true;
                for (int i = 0; i < 10; i++) {
                    if (addrBytes[i] != 0) {
                        isMapped = false;
                        break;
                    }
                }
                if (isMapped
                        && (addrBytes[10] & 0xFF) == 0xFF
                        && (addrBytes[11] & 0xFF) == 0xFF) {
                    int mappedFirst = addrBytes[12] & 0xFF;
                    int mappedSecond = addrBytes[13] & 0xFF;
                    if (mappedFirst == 169 && mappedSecond == 254) {
                        return false;
                    }
                    if (mappedFirst == 127) {
                        return false;
                    }
                    if (mappedFirst == 10) {
                        return false;
                    }
                    if (mappedFirst == 172 && mappedSecond >= 16 && mappedSecond <= 31) {
                        return false;
                    }
                    if (mappedFirst == 192 && mappedSecond == 168) {
                        return false;
                    }
                }
            }
            return true;
        } catch (UnknownHostException e) {
            return false;
        }
    }
}
