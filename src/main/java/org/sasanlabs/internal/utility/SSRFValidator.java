package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Set;

/**
 * Utility class to validate URLs against SSRF attacks. Rejects non-http(s) schemes and URLs that
 * resolve to private/internal IP addresses.
 */
public final class SSRFValidator {

    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    private SSRFValidator() {}

    /**
     * Validates that the given URL string is well-formed, uses http or https scheme, and does not
     * resolve to a private/internal IP address.
     *
     * @param urlString the URL string to validate
     * @return true if the URL is safe to fetch, false otherwise
     */
    public static boolean isSafeUrl(String urlString) {
        URL url;
        try {
            url = new URL(urlString);
            url.toURI();
        } catch (MalformedURLException | URISyntaxException e) {
            return false;
        }

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
            if (isPrivateOrReserved(address)) {
                return false;
            }
        } catch (UnknownHostException e) {
            // Cannot resolve host - reject to be safe
            return false;
        }

        return true;
    }

    private static boolean isPrivateOrReserved(InetAddress address) {
        return address.isLoopbackAddress()
                || address.isSiteLocalAddress()
                || address.isLinkLocalAddress()
                || address.isAnyLocalAddress()
                || address.isMulticastAddress()
                || isCloudMetadataAddress(address);
    }

    private static boolean isCloudMetadataAddress(InetAddress address) {
        byte[] addr = address.getAddress();
        if (addr.length == 4) {
            // 169.254.169.254 (AWS/GCP/Azure metadata)
            // 169.254.170.2 (AWS ECS metadata)
            if ((addr[0] & 0xFF) == 169 && (addr[1] & 0xFF) == 254) {
                return true;
            }
        }
        return false;
    }
}
