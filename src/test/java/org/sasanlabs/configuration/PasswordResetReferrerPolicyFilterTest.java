package org.sasanlabs.configuration;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.*;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
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
    void shouldSetUnsafeUrlPolicyForValidLevel7OnResetPage()
            throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("7");

        filter.doFilter(request, response, filterChain);

        verify(response).setHeader("Referrer-Policy", "unsafe-url");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotSetHeaderWhenLevelIsNull() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn(null);

        filter.doFilter(request, response, filterChain);

        verify(response, never()).setHeader(eq("Referrer-Policy"), anyString());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotSetHeaderForNonResetPage() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/other-page.html");
        when(request.getParameter("level")).thenReturn("7");

        filter.doFilter(request, response, filterChain);

        verify(response, never()).setHeader(eq("Referrer-Policy"), anyString());
        verify(filterChain).doFilter(request, response);
    }

    @ParameterizedTest
    @ValueSource(
            strings = {
                "abc",
                "7abc",
                "abc7",
                " 7",
                "7 ",
                "-7",
                "+7",
                "7.0",
                "7\n",
                "<script>",
                "99999999999999999999999"
            })
    void shouldRejectMalformedLevelParameter(String malformedLevel)
            throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn(malformedLevel);

        filter.doFilter(request, response, filterChain);

        verify(response, never()).setHeader(eq("Referrer-Policy"), anyString());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotSetHeaderForNonMatchingValidLevel() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("5");

        filter.doFilter(request, response, filterChain);

        verify(response, never()).setHeader(eq("Referrer-Policy"), anyString());
        verify(filterChain).doFilter(request, response);
    }
}
