package org.sasanlabs.configuration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class PasswordResetReferrerPolicyFilterTest {

    private PasswordResetReferrerPolicyFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        filter = new PasswordResetReferrerPolicyFilter();
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        filterChain = new MockFilterChain();
    }

    @Test
    void shouldSetUnsafeUrlReferrerPolicyForLevel7() throws ServletException, IOException {
        request.setRequestURI("/password-reset/reset.html");
        request.setParameter("level", "7");

        filter.doFilter(request, response, filterChain);

        assertEquals("unsafe-url", response.getHeader("Referrer-Policy"));
    }

    @Test
    void shouldNotSetHeaderWhenLevelIsNull() throws ServletException, IOException {
        request.setRequestURI("/password-reset/reset.html");

        filter.doFilter(request, response, filterChain);

        assertNull(response.getHeader("Referrer-Policy"));
    }

    @Test
    void shouldNotSetHeaderForNonMatchingLevel() throws ServletException, IOException {
        request.setRequestURI("/password-reset/reset.html");
        request.setParameter("level", "3");

        filter.doFilter(request, response, filterChain);

        assertNull(response.getHeader("Referrer-Policy"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"abc", "7abc", "<script>", "'; DROP TABLE", ""})
    void shouldRejectInvalidLevelValues(String invalidLevel)
            throws ServletException, IOException {
        request.setRequestURI("/password-reset/reset.html");
        request.setParameter("level", invalidLevel);

        filter.doFilter(request, response, filterChain);

        assertNull(response.getHeader("Referrer-Policy"));
    }

    @Test
    void shouldRejectExcessivelyLongLevelValue() throws ServletException, IOException {
        request.setRequestURI("/password-reset/reset.html");
        request.setParameter("level", "12345678901");

        filter.doFilter(request, response, filterChain);

        assertNull(response.getHeader("Referrer-Policy"));
    }

    @Test
    void shouldNotSetHeaderForNonResetPath() throws ServletException, IOException {
        request.setRequestURI("/other-page.html");
        request.setParameter("level", "7");

        filter.doFilter(request, response, filterChain);

        assertNull(response.getHeader("Referrer-Policy"));
    }
}
