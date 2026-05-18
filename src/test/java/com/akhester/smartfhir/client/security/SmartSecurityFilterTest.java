package com.akhester.smartfhir.client.security;

import com.akhester.smartfhir.client.context.SmartContextExtractor;
import com.akhester.smartfhir.client.context.SmartLaunchContext;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.core.context.SecurityContextHolder;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

/**
 * Unit tests for SmartSecurityFilter.
 *
 * Test cases:
 *  1.  Valid session → SecurityContext populated with SmartAuthenticationToken.
 *  2.  Valid session → filter chain continues (request not blocked).
 *  3.  No session → SecurityContext remains empty, filter chain continues.
 *  4.  Session with no launch context → SecurityContext empty.
 *  5.  Expired token in session → SecurityContext cleared, filter chain continues.
 *  6.  Token expiring within buffer (30s) → treated as expired.
 *  7.  After filter: Authentication.getPrincipal() is the patient ID.
 */
@ExtendWith(MockitoExtension.class)
class SmartSecurityFilterTest {

    @Mock SmartContextExtractor contextExtractor;
    @Mock FilterChain filterChain;

    private SmartSecurityFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        filter   = new SmartSecurityFilter(contextExtractor);
        request  = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    private SmartLaunchContext validContext() {
        return new SmartLaunchContext(
                "eyJ.token", "ePatient-123", null,
                "https://fhir.epic.com/fhir/r4",
                true, "launch openid",
                Instant.now().plusSeconds(3600), null
        );
    }

    private SmartLaunchContext expiredContext() {
        return new SmartLaunchContext(
                "eyJ.old_token", "ePatient-123", null,
                "https://fhir.epic.com/fhir/r4",
                true, "launch openid",
                Instant.now().minusSeconds(60), null  // already expired
        );
    }

    private SmartLaunchContext nearlyExpiredContext() {
        return new SmartLaunchContext(
                "eyJ.expiring_token", "ePatient-123", null,
                "https://fhir.epic.com/fhir/r4",
                true, "launch openid",
                Instant.now().plusSeconds(20), null  // within 30s buffer
        );
    }

    // ── happy path ────────────────────────────────────────────────────────────

    @Test
    void validSession_populatesSecurityContext() throws Exception {
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        when(contextExtractor.retrieve(any())).thenReturn(validContext());

        filter.doFilter(request, response, filterChain);

        var auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isInstanceOf(SmartAuthenticationToken.class);
        assertThat(auth.isAuthenticated()).isTrue();
    }

    @Test
    void validSession_filterChainContinues() throws Exception {
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        when(contextExtractor.retrieve(any())).thenReturn(validContext());

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
    }

    @Test
    void validSession_principalIsPatientId() throws Exception {
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        when(contextExtractor.retrieve(any())).thenReturn(validContext());

        filter.doFilter(request, response, filterChain);

        var auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth.getPrincipal()).isEqualTo("ePatient-123");
    }

    // ── no / empty session ────────────────────────────────────────────────────

    @Test
    void noSession_securityContextRemainsEmpty() throws Exception {
        // request has no session — getSession(false) returns null
        filter.doFilter(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void sessionWithNoLaunchContext_securityContextEmpty() throws Exception {
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        when(contextExtractor.retrieve(any())).thenReturn(null);

        filter.doFilter(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(filterChain).doFilter(request, response);
    }

    // ── expired token ─────────────────────────────────────────────────────────

    @Test
    void expiredToken_securityContextClearedAndChainContinues() throws Exception {
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        when(contextExtractor.retrieve(any())).thenReturn(expiredContext());

        filter.doFilter(request, response, filterChain);

        // SecurityContext must be clear — expired token is not authenticated.
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        // Chain must continue so Spring Security can return 401 for protected routes.
        verify(filterChain).doFilter(request, response);
    }

    @Test
    void tokenWithinExpiryBuffer_treatedAsExpired() throws Exception {
        // Token expiring in 20s is within the 30s buffer — treated as expired.
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        when(contextExtractor.retrieve(any())).thenReturn(nearlyExpiredContext());

        filter.doFilter(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }
}
