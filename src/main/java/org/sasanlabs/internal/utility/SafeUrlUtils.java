package org.sasanlabs.internal.utility;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLConnection;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Locale;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Helpers that keep request driven outbound fetches on an operator configured destination allowlist
 * (CWE-918, Server Side Request Forgery).
 *
 * <p>Only {@code http} and {@code https} destinations whose host is explicitly allowed may be
 * fetched. Everything else is refused, which by construction also refuses {@code file://} and the
 * other local schemes. Hosts are additionally resolved before every connection so that a name on
 * the allowlist cannot be pointed at loopback, link local, private or cloud metadata addresses, and
 * redirects are validated hop by hop instead of being followed blindly.
 *
 * <p>Every check fails closed by throwing {@link IllegalArgumentException}.
 *
 * <p>Rejection messages name the broken rule and never echo the untrusted value back.
 */
public final class SafeUrlUtils {

    /** Schemes that may be fetched. Anything else, {@code file://} included, is refused. */
    private static final Set<String> ALLOWED_SCHEMES = Set.of("http", "https");

    /** Well known cloud metadata addresses, refused even when a name resolves to them. */
    private static final Set<String> METADATA_ADDRESSES =
            Set.of("169.254.169.254", "169.254.170.2", "100.100.100.200", "fd00:ec2:0:0:0:0:0:254");

    private static final int MAX_REDIRECTS = 5;
    private static final int CONNECT_TIMEOUT_MS = 5_000;
    private static final int READ_TIMEOUT_MS = 10_000;
    private static final String LOCATION_HEADER = "Location";

    private SafeUrlUtils() {}

    /**
     * Parses a comma separated, operator configured list of allowed hosts.
     *
     * @param commaSeparatedHosts configured hosts, may be {@code null} or blank.
     * @return an immutable set of lower cased host names, empty when nothing is configured.
     */
    public static Set<String> parseAllowedHosts(String commaSeparatedHosts) {
        if (commaSeparatedHosts == null) {
            return Collections.emptySet();
        }
        return Collections.unmodifiableSet(
                Arrays.stream(commaSeparatedHosts.split(","))
                        .map(String::trim)
                        .filter(host -> !host.isEmpty())
                        .map(host -> host.toLowerCase(Locale.ROOT))
                        .collect(Collectors.toCollection(LinkedHashSet::new)));
    }

    /**
     * Validates a request supplied URL against the destination allowlist.
     *
     * @param rawUrl untrusted URL.
     * @param allowedHosts hosts that may be fetched, an empty set refuses everything.
     * @return the parsed URL, guaranteed to be an allowed {@code http(s)} destination.
     * @throws IllegalArgumentException if the URL is unusable or its host is not allowed.
     */
    public static URL requireAllowedDestination(String rawUrl, Set<String> allowedHosts) {
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("url must not be null or blank");
        }
        if (allowedHosts == null || allowedHosts.isEmpty()) {
            throw new IllegalArgumentException("no destination host is allowed by configuration");
        }
        String candidate = rawUrl.trim();
        rejectControlCharacters(candidate);
        URL url;
        try {
            url = new URL(candidate);
            // Rejects the syntax URL is lenient about, e.g. spaces or illegal escapes.
            url.toURI();
        } catch (MalformedURLException | URISyntaxException e) {
            throw new IllegalArgumentException("url must be a valid absolute URL", e);
        }
        String scheme = url.getProtocol().toLowerCase(Locale.ROOT);
        if (!ALLOWED_SCHEMES.contains(scheme)) {
            throw new IllegalArgumentException("url scheme must be one of " + ALLOWED_SCHEMES);
        }
        if (url.getUserInfo() != null) {
            throw new IllegalArgumentException("url must not carry credentials");
        }
        String host = url.getHost() == null ? "" : url.getHost().toLowerCase(Locale.ROOT);
        if (host.isEmpty()) {
            throw new IllegalArgumentException("url must carry a host");
        }
        if (!allowedHosts.contains(host)) {
            throw new IllegalArgumentException("url host is not on the destination allowlist");
        }
        return url;
    }

    /**
     * Resolves the host of an already allowlisted URL and refuses internal destinations.
     *
     * <p>Called right before connecting, so a name that resolves to an internal address, whether by
     * configuration mistake or by DNS rebinding, still cannot be reached.
     *
     * @param url URL returned by {@link #requireAllowedDestination(String, Set)}.
     * @throws IllegalArgumentException if the host does not resolve or resolves to an address that
     *     must not be reached.
     */
    public static void requireAllowedAddress(URL url) {
        if (url == null) {
            throw new IllegalArgumentException("url must not be null");
        }
        InetAddress[] addresses;
        try {
            addresses = InetAddress.getAllByName(url.getHost());
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("url host cannot be resolved", e);
        }
        for (InetAddress address : addresses) {
            if (isForbidden(address)) {
                throw new IllegalArgumentException(
                        "url host resolves to an internal or metadata address");
            }
        }
    }

    /**
     * Fetches the body of an allowlisted URL, re-validating every redirect hop.
     *
     * @param url URL returned by {@link #requireAllowedDestination(String, Set)}.
     * @param allowedHosts hosts that may be fetched, redirects included.
     * @return the response body.
     * @throws IllegalArgumentException if the URL or any redirect target is not allowed.
     * @throws IOException if the resource cannot be read or keeps redirecting.
     */
    public static String readAllowedResource(URL url, Set<String> allowedHosts) throws IOException {
        URL current =
                requireAllowedDestination(url == null ? null : url.toExternalForm(), allowedHosts);
        for (int hop = 0; hop <= MAX_REDIRECTS; hop++) {
            requireAllowedAddress(current);
            URLConnection urlConnection = current.openConnection();
            if (!(urlConnection instanceof HttpURLConnection)) {
                throw new IllegalArgumentException("url scheme must be one of " + ALLOWED_SCHEMES);
            }
            HttpURLConnection connection = (HttpURLConnection) urlConnection;
            connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
            connection.setReadTimeout(READ_TIMEOUT_MS);
            // Redirects are followed by hand so every hop is checked against the allowlist.
            connection.setInstanceFollowRedirects(false);
            try {
                URL redirectTarget = redirectTarget(connection, current, allowedHosts);
                if (redirectTarget != null) {
                    current = redirectTarget;
                    continue;
                }
                try (BufferedReader reader =
                        new BufferedReader(
                                new InputStreamReader(
                                        connection.getInputStream(), StandardCharsets.UTF_8))) {
                    return reader.lines().collect(Collectors.joining());
                }
            } finally {
                connection.disconnect();
            }
        }
        throw new IOException("too many redirects while reading the requested url");
    }

    /**
     * Returns the validated target of a redirect response, or {@code null} when the response is not
     * a redirect.
     */
    private static URL redirectTarget(
            HttpURLConnection connection, URL current, Set<String> allowedHosts)
            throws IOException {
        int status = connection.getResponseCode();
        if (status < HttpURLConnection.HTTP_MULT_CHOICE || status >= 400) {
            return null;
        }
        String location = connection.getHeaderField(LOCATION_HEADER);
        if (location == null || location.trim().isEmpty()) {
            throw new IOException("redirect response without a location header");
        }
        return requireAllowedDestination(new URL(current, location).toExternalForm(), allowedHosts);
    }

    private static boolean isForbidden(InetAddress address) {
        return address.isAnyLocalAddress()
                || address.isLoopbackAddress()
                || address.isLinkLocalAddress()
                || address.isSiteLocalAddress()
                || address.isMulticastAddress()
                || isUniqueLocalIpv6(address)
                || isSharedAddressSpaceIpv4(address)
                || METADATA_ADDRESSES.contains(address.getHostAddress().toLowerCase(Locale.ROOT));
    }

    /** IPv6 unique local addresses, fc00::/7. */
    private static boolean isUniqueLocalIpv6(InetAddress address) {
        byte[] bytes = address.getAddress();
        return bytes.length == 16 && (bytes[0] & 0xFE) == 0xFC;
    }

    /** IPv4 shared address space, 100.64.0.0/10, used by carrier grade NAT. */
    private static boolean isSharedAddressSpaceIpv4(InetAddress address) {
        byte[] bytes = address.getAddress();
        return bytes.length == 4
                && (bytes[0] & 0xFF) == 100
                && (bytes[1] & 0xFF) >= 64
                && (bytes[1] & 0xFF) <= 127;
    }

    private static void rejectControlCharacters(String value) {
        for (int index = 0; index < value.length(); index++) {
            if (value.charAt(index) < ' ' || value.charAt(index) == 0x7F) {
                throw new IllegalArgumentException("url must not contain control characters");
            }
        }
    }
}
