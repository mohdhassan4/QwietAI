package org.sasanlabs.configuration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

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
    void shouldSetUnsafeUrlReferrerPolicyForLevel7OnResetPage()
            throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("7");

        filter.doFilterInternal(request, response, filterChain);

        verify(response).setHeader("Referrer-Policy", "unsafe-url");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotSetHeaderWhenLevelIsNull() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn(null);

        filter.doFilterInternal(request, response, filterChain);

        verify(response, never()).setHeader("Referrer-Policy", "unsafe-url");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotSetHeaderWhenPathDoesNotMatch() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/other-page.html");
        when(request.getParameter("level")).thenReturn("7");

        filter.doFilterInternal(request, response, filterChain);

        verify(response, never()).setHeader("Referrer-Policy", "unsafe-url");
        verify(filterChain).doFilter(request, response);
    }

    @ParameterizedTest
    @ValueSource(strings = {"abc", "7abc", "<script>", "1+1", "-1", "7.0", " 7"})
    void shouldRejectInvalidLevelFormats(String invalidLevel)
            throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn(invalidLevel);

        filter.doFilterInternal(request, response, filterChain);

        verify(response, never()).setHeader("Referrer-Policy", "unsafe-url");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldRejectExcessivelyLongInput() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("12345678901");

        filter.doFilterInternal(request, response, filterChain);

        verify(response, never()).setHeader("Referrer-Policy", "unsafe-url");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotSetHeaderForLevelOtherThan7() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("5");

        filter.doFilterInternal(request, response, filterChain);

        verify(response, never()).setHeader("Referrer-Policy", "unsafe-url");
        verify(filterChain).doFilter(request, response);
    }
}
