package org.sasanlabs.configuration;

import java.io.IOException;
import java.util.regex.Pattern;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Overrides referrer policy on the reset page so level 7 can demonstrate full-URL referrer leakage
 * to third-party resources.
 */
@Component
@Order(Ordered.LOWEST_PRECEDENCE - 100)
public class PasswordResetReferrerPolicyFilter extends OncePerRequestFilter {

    private static final String RESET_PAGE_PATH = "/password-reset/reset.html";
    private static final int REFERRER_LEAK_LEVEL = 7;
    private static final int INVALID_LEVEL = -1;

    /**
     * Strict allowlist for the {@code level} request parameter: only the supported levels 1 to 10,
     * expressed as plain digits with no sign, padding, whitespace or control characters.
     */
    private static final Pattern SUPPORTED_LEVEL_PATTERN = Pattern.compile("(?:[1-9]|10)");

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (shouldApplyUnsafeUrlReferrerPolicy(request)) {
            response.setHeader("Referrer-Policy", "unsafe-url");
        }
        filterChain.doFilter(request, response);
    }

    private boolean shouldApplyUnsafeUrlReferrerPolicy(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        if (requestUri == null || !requestUri.endsWith(RESET_PAGE_PATH)) {
            return false;
        }

        return parseSupportedLevel(request.getParameter("level")) == REFERRER_LEAK_LEVEL;
    }

    /**
     * Validates the untrusted {@code level} request parameter against {@link
     * #SUPPORTED_LEVEL_PATTERN} before it is used in any decision. Values that are absent,
     * malformed, out of the supported range or that carry unexpected characters are rejected, so
     * the filter fails closed and leaves the application default referrer policy in place.
     *
     * @param rawLevel the raw, attacker controlled parameter value, may be {@code null}
     * @return the validated level, or {@link #INVALID_LEVEL} when the value is not allowlisted
     */
    private static int parseSupportedLevel(String rawLevel) {
        if (rawLevel == null || !SUPPORTED_LEVEL_PATTERN.matcher(rawLevel).matches()) {
            return INVALID_LEVEL;
        }
        return Integer.parseInt(rawLevel);
    }
}
