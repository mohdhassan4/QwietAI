package org.sasanlabs.configuration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class PasswordResetReferrerPolicyFilterTest {

    private PasswordResetReferrerPolicyFilter filter;
    private HttpServletRequest request;
    private HttpServletResponse response;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        filter = new PasswordResetReferrerPolicyFilter();
        request = mock(HttpServletRequest.class);
        response = mock(HttpServletResponse.class);
        filterChain = mock(FilterChain.class);
    }

    @Test
    void shouldSetUnsafeUrlPolicyForLevel7OnResetPage() throws Exception {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("7");

        filter.doFilterInternal(request, response, filterChain);

        verify(response).setHeader("Referrer-Policy", "unsafe-url");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotSetPolicyForNullLevel() throws Exception {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn(null);

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotSetPolicyForNonNumericLevel() throws Exception {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("abc");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotSetPolicyForLevelWithSpecialCharacters() throws Exception {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("7; DROP TABLE users");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotSetPolicyForLevelOutOfRange() throws Exception {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("999");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotSetPolicyForNegativeLevel() throws Exception {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("-1");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotSetPolicyForDifferentPath() throws Exception {
        when(request.getRequestURI()).thenReturn("/other/page.html");
        when(request.getParameter("level")).thenReturn("7");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotSetPolicyForLevelNotEqualTo7() throws Exception {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("3");

        filter.doFilterInternal(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }
}
