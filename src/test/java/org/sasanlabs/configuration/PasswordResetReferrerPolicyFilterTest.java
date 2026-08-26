package org.sasanlabs.configuration;

import static org.assertj.core.api.Assertions.assertThat;

import javax.servlet.FilterChain;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class PasswordResetReferrerPolicyFilterTest {

    private PasswordResetReferrerPolicyFilter filter;
    private MockHttpServletResponse response;
    private FilterChain filterChain;

    @BeforeEach
    void setUp() {
        filter = new PasswordResetReferrerPolicyFilter();
        response = new MockHttpServletResponse();
        filterChain = Mockito.mock(FilterChain.class);
    }

    @Test
    void shouldSetUnsafeUrlPolicyWhenLevelIs7() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/password-reset/reset.html");
        request.setParameter("level", "7");

        filter.doFilterInternal(request, response, filterChain);

        assertThat(response.getHeader("Referrer-Policy")).isEqualTo("unsafe-url");
    }

    @Test
    void shouldNotSetHeaderWhenLevelIsNot7() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/password-reset/reset.html");
        request.setParameter("level", "3");

        filter.doFilterInternal(request, response, filterChain);

        assertThat(response.getHeader("Referrer-Policy")).isNull();
    }

    @ParameterizedTest
    @NullAndEmptySource
    void shouldNotSetHeaderWhenLevelIsNullOrEmpty(String level) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/password-reset/reset.html");
        if (level != null) {
            request.setParameter("level", level);
        }

        filter.doFilterInternal(request, response, filterChain);

        assertThat(response.getHeader("Referrer-Policy")).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = {"abc", "7abc", "<script>", "7; DROP TABLE", "-1", "12345678901"})
    void shouldRejectInvalidLevelInput(String level) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/password-reset/reset.html");
        request.setParameter("level", level);

        filter.doFilterInternal(request, response, filterChain);

        assertThat(response.getHeader("Referrer-Policy")).isNull();
    }

    @Test
    void shouldNotSetHeaderWhenPathDoesNotMatch() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/other/page.html");
        request.setParameter("level", "7");

        filter.doFilterInternal(request, response, filterChain);

        assertThat(response.getHeader("Referrer-Policy")).isNull();
    }
}
