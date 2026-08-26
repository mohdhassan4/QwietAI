package org.sasanlabs.configuration;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
    void shouldSetUnsafeUrlReferrerPolicyForLevel7() throws Exception {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("7");

        filter.doFilterInternal(request, response, filterChain);

        verify(response).setHeader("Referrer-Policy", "unsafe-url");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotSetHeaderWhenLevelIsNull() throws Exception {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn(null);

        filter.doFilterInternal(request, response, filterChain);

        verify(response, never()).setHeader("Referrer-Policy", "unsafe-url");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotSetHeaderWhenLevelIsNonNumeric() throws Exception {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("abc");

        filter.doFilterInternal(request, response, filterChain);

        verify(response, never()).setHeader("Referrer-Policy", "unsafe-url");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldRejectLevelWithSpecialCharacters() throws Exception {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("7; DROP TABLE");

        filter.doFilterInternal(request, response, filterChain);

        verify(response, never()).setHeader("Referrer-Policy", "unsafe-url");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldRejectExcessivelyLongLevel() throws Exception {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("77777777777");

        filter.doFilterInternal(request, response, filterChain);

        verify(response, never()).setHeader("Referrer-Policy", "unsafe-url");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldRejectEmptyLevel() throws Exception {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("");

        filter.doFilterInternal(request, response, filterChain);

        verify(response, never()).setHeader("Referrer-Policy", "unsafe-url");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotSetHeaderForDifferentPath() throws Exception {
        when(request.getRequestURI()).thenReturn("/other/page.html");
        when(request.getParameter("level")).thenReturn("7");

        filter.doFilterInternal(request, response, filterChain);

        verify(response, never()).setHeader("Referrer-Policy", "unsafe-url");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldRejectNegativeLevel() throws Exception {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("-7");

        filter.doFilterInternal(request, response, filterChain);

        verify(response, never()).setHeader("Referrer-Policy", "unsafe-url");
        verify(filterChain).doFilter(request, response);
    }
}
