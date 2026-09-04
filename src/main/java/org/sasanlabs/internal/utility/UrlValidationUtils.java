package org.sasanlabs.internal.utility;

import java.net.InetAddress;
import java.net.URL;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.Set;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility class validating the URLs provided by the users before the application performs a server
 * side request to them, hence avoiding Server Side Request Forgery (CWE-918).
 *
 * <p>A URL is only allowed if it is an absolute {@code http}/{@code https} URL, it does not carry
 * embedded credentials, its host is present in the provided allow list and the host does not
 * resolve to an internal address, like a wildcard, loopback, link local (eg the cloud metadata
 * service {@code 169.254.169.254}), private, unique local, shared or multicast address.
 */
public final class UrlValidationUtils {

    private static final Logger LOGGER = LogManager.getLogger(UrlValidationUtils.class);

    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    private static final int OCTET_MASK = 0xff;

    private static final int UNIQUE_LOCAL_PREFIX_MASK = 0xfe;

    private static final int UNIQUE_LOCAL_PREFIX = 0xfc;

    private static final int IPV6_ADDRESS_LENGTH = 16;

    private UrlValidationUtils() {}

    /**
     * Tells if the application is allowed to perform a server side request to the provided URL.
     *
     * @param url the URL provided by the user.
     * @param allowedHosts the hosts the application is allowed to fetch, compared in a case
     *     insensitive manner.
     * @return {@code true} only if the URL is an allowed destination, {@code false} otherwise.
     */
    public static boolean isAllowedDestination(URL url, Set<String> allowedHosts) {
        String scheme = url.getProtocol();
        if (scheme == null || !ALLOWED_SCHEMES.contains(scheme.toLowerCase(Locale.ROOT))) {
            LOGGER.error("URL rejected: scheme is not http/https");
            return false;
        }
        if (url.getUserInfo() != null) {
            LOGGER.error("URL rejected: embedded credentials are not supported");
            return false;
        }
        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            LOGGER.error("URL rejected: host is missing");
            return false;
        }
        if (allowedHosts.stream().noneMatch(host::equalsIgnoreCase)) {
            LOGGER.error("URL rejected: host is not present in the allow list");
            return false;
        }
        return !resolvesToInternalAddress(host);
    }

    private static boolean resolvesToInternalAddress(String host) {
        String hostToResolve = host;
        if (hostToResolve.startsWith("[") && hostToResolve.endsWith("]")) {
            hostToResolve = hostToResolve.substring(1, hostToResolve.length() - 1);
        }
        try {
            for (InetAddress address : InetAddress.getAllByName(hostToResolve)) {
                if (isInternalAddress(address)) {
                    LOGGER.error("URL rejected: host resolves to an internal address");
                    return true;
                }
            }
            return false;
        } catch (UnknownHostException e) {
            LOGGER.error("URL rejected: host could not be resolved", e);
            return true;
        }
    }

    private static boolean isInternalAddress(InetAddress address) {
        return address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()
                || isSharedOrUniqueLocalAddress(address.getAddress());
    }

    private static boolean isSharedOrUniqueLocalAddress(byte[] addressBytes) {
        int firstByte = addressBytes[0] & OCTET_MASK;
        if (addressBytes.length == IPV6_ADDRESS_LENGTH) {
            // fc00::/7, ie the unique local addresses
            return (firstByte & UNIQUE_LOCAL_PREFIX_MASK) == UNIQUE_LOCAL_PREFIX;
        }
        int secondByte = addressBytes[1] & OCTET_MASK;
        // 0.0.0.0/8, ie this network, and 100.64.0.0/10, ie the carrier grade NAT range
        return firstByte == 0 || (firstByte == 100 && secondByte >= 64 && secondByte <= 127);
    }
}
