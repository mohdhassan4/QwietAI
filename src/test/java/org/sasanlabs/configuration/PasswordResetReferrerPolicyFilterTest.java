package org.sasanlabs.configuration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.io.IOException;
import javax.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Verifies that the untrusted {@code level} request parameter is validated against a strict
 * allowlist and that anything else fails closed, while the level 7 referrer leakage lesson keeps
 * working.
 */
class PasswordResetReferrerPolicyFilterTest {

    private static final String RESET_PAGE_URI = "/VulnerableApp/password-reset/reset.html";
    private static final String REFERRER_POLICY_HEADER = "Referrer-Policy";

    @Test
    void leakLevelStillGetsTheUnsafeUrlReferrerPolicy() throws Exception {
        assertEquals("unsafe-url", referrerPolicyFor("7"));
    }

    @Test
    void otherSupportedLevelsKeepTheDefaultReferrerPolicy() throws Exception {
        assertNull(referrerPolicyFor("1"));
        assertNull(referrerPolicyFor("6"));
        assertNull(referrerPolicyFor("8"));
        assertNull(referrerPolicyFor("10"));
    }

    @Test
    void missingLevelFailsClosed() throws Exception {
        assertNull(referrerPolicyFor(null));
    }

    @Test
    void malformedLevelFailsClosed() throws Exception {
        assertNull(referrerPolicyFor(""));
        assertNull(referrerPolicyFor("07"));
        assertNull(referrerPolicyFor(" 7"));
        assertNull(referrerPolicyFor("7 "));
        assertNull(referrerPolicyFor("+7"));
        assertNull(referrerPolicyFor("-7"));
        assertNull(referrerPolicyFor("7abc"));
        assertNull(referrerPolicyFor("seven"));
        assertNull(referrerPolicyFor("11"));
        assertNull(referrerPolicyFor("70"));
    }

    @Test
    void controlCharactersInLevelFailClosed() throws Exception {
        assertNull(referrerPolicyFor("7\r\nX-Injected: yes"));
        assertNull(referrerPolicyFor("7\n"));
        assertNull(referrerPolicyFor("\t7"));
    }

    @Test
    void nonResetPagesAreNeverTouched() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/VulnerableApp/");
        request.setParameter("level", "7");
        MockHttpServletResponse response = new MockHttpServletResponse();
        PasswordResetReferrerPolicyFilter filter = new PasswordResetReferrerPolicyFilter();
        filter.doFilterInternal(request, response, new MockFilterChain());
        assertNull(response.getHeader(REFERRER_POLICY_HEADER));
    }

    private String referrerPolicyFor(String rawLevel) throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", RESET_PAGE_URI);
        if (rawLevel != null) {
            request.setParameter("level", rawLevel);
        }
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        PasswordResetReferrerPolicyFilter filter = new PasswordResetReferrerPolicyFilter();
        filter.doFilterInternal(request, response, filterChain);
        assertSame(request, filterChain.getRequest());
        return response.getHeader(REFERRER_POLICY_HEADER);
    }
}
