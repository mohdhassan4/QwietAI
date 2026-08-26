package org.sasanlabs.configuration;

import static org.mockito.Mockito.*;

import java.io.IOException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
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
    void shouldSetReferrerPolicyForValidLevel7() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("7");

        filter.doFilter(request, response, filterChain);

        verify(response).setHeader("Referrer-Policy", "unsafe-url");
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotSetHeaderForNonMatchingLevel() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("3");

        filter.doFilter(request, response, filterChain);

        verify(response, never()).setHeader(eq("Referrer-Policy"), anyString());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldRejectNonNumericLevel() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("abc");

        filter.doFilter(request, response, filterChain);

        verify(response, never()).setHeader(eq("Referrer-Policy"), anyString());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldRejectLevelWithSpecialCharacters() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("7; DROP TABLE");

        filter.doFilter(request, response, filterChain);

        verify(response, never()).setHeader(eq("Referrer-Policy"), anyString());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldRejectExcessivelyLongLevel() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("12345678901234567890");

        filter.doFilter(request, response, filterChain);

        verify(response, never()).setHeader(eq("Referrer-Policy"), anyString());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldRejectNullLevel() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn(null);

        filter.doFilter(request, response, filterChain);

        verify(response, never()).setHeader(eq("Referrer-Policy"), anyString());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldRejectEmptyLevel() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("");

        filter.doFilter(request, response, filterChain);

        verify(response, never()).setHeader(eq("Referrer-Policy"), anyString());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldRejectNegativeLevel() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/password-reset/reset.html");
        when(request.getParameter("level")).thenReturn("-7");

        filter.doFilter(request, response, filterChain);

        verify(response, never()).setHeader(eq("Referrer-Policy"), anyString());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void shouldNotApplyForDifferentPath() throws ServletException, IOException {
        when(request.getRequestURI()).thenReturn("/other/page.html");
        when(request.getParameter("level")).thenReturn("7");

        filter.doFilter(request, response, filterChain);

        verify(response, never()).setHeader(eq("Referrer-Policy"), anyString());
        verify(filterChain).doFilter(request, response);
    }
}
