package com.akhester.smartfhir.client.refresh;

import com.akhester.smartfhir.client.context.SmartContextExtractor;
import com.akhester.smartfhir.client.context.SmartLaunchContext;
import com.akhester.smartfhir.client.discovery.SmartConfiguration;
import com.akhester.smartfhir.client.discovery.SmartDiscoveryService;
import com.akhester.smartfhir.client.security.SmartAuthenticationToken;
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
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for TokenRefreshFilter.
 *
 * Test cases:
 *  1.  Non-API path → filter skips (shouldNotFilter returns true).
 *  2.  No authentication in SecurityContext → filter passes through.
 *  3.  Valid token, no refresh needed → context unchanged in SecurityContext.
 *  4.  Token refreshed → SecurityContext updated with new context.
 *  5.  Refresh returns null (no refresh token) → SecurityContext cleared, session invalidated.
 *  6.  Refresh throws exception → SecurityContext cleared, session invalidated.
 *  7.  Discovery failure → filter passes through with existing token.
 *  8.  All paths call filterChain.doFilter() exactly once.
 */
@ExtendWith(MockitoExtension.class)
class TokenRefreshFilterTest {

    @Mock TokenRefreshService refreshService;
    @Mock SmartContextExtractor contextExtractor;
    @Mock SmartDiscoveryService discoveryService;
    @Mock FilterChain filterChain;

    private TokenRefreshFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MockHttpSession session;

    private static final String TOKEN_ENDPOINT = "https://fhir.epic.com/oauth2/token";

    @BeforeEach
    void setUp() {
        filter   = new TokenRefreshFilter(refreshService, contextExtractor, discoveryService);
        request  = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        session  = new MockHttpSession();
        request.setSession(session);
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() { SecurityContextHolder.clearContext(); }

    private SmartLaunchContext context(Instant expiresAt) {
        return new SmartLaunchContext(
                "eyJ.token", "ePatient-123", null,
                "https://fhir.epic.com/fhir/r4",
                true, "launch openid",
                expiresAt, "refresh_token",
                null);
    }

    private void setAuthentication(SmartLaunchContext ctx) {
        SecurityContextHolder.getContext()
                .setAuthentication(new SmartAuthenticationToken(ctx));
    }

    private void stubDiscovery() {
        SmartConfiguration config = new SmartConfiguration(
                "https://fhir.epic.com/oauth2/authorize",
                TOKEN_ENDPOINT, null, null, null,
                List.of("launch-ehr"), List.of("S256")
        );
        when(discoveryService.discover(anyString())).thenReturn(config);
    }

    // ── shouldNotFilter ───────────────────────────────────────────────────────

    @Test
    void nonApiPath_filterSkips() throws Exception {
        request.setRequestURI("/health");
        assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    @Test
    void apiPath_filterRuns() {
        request.setRequestURI("/api/patient");
        assertThat(filter.shouldNotFilter(request)).isFalse();
    }

    @Test
    void launchPath_filterSkips() throws Exception {
        request.setRequestURI("/launch");
        assertThat(filter.shouldNotFilter(request)).isTrue();
    }

    // ── unauthenticated request ───────────────────────────────────────────────

    @Test
    void noAuthentication_passesThrough() throws Exception {
        request.setRequestURI("/api/patient");
        // No auth in SecurityContext
        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(refreshService);
    }

    // ── token still valid ─────────────────────────────────────────────────────

    @Test
    void tokenStillValid_contextUnchanged() throws Exception {
        request.setRequestURI("/api/patient");
        SmartLaunchContext fresh = context(Instant.now().plusSeconds(3600));
        setAuthentication(fresh);
        stubDiscovery();
        when(refreshService.refreshIfNeeded(any(), anyString(), any())).thenReturn(fresh);

        filter.doFilter(request, response, filterChain);

        // SecurityContext still has the same patient
        var auth = SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth).isInstanceOf(SmartAuthenticationToken.class);
        assertThat(auth.getPrincipal()).isEqualTo("ePatient-123");
        verify(filterChain).doFilter(request, response);
    }

    // ── token refreshed ───────────────────────────────────────────────────────

    @Test
    void tokenRefreshed_securityContextUpdatedWithNewContext() throws Exception {
        request.setRequestURI("/api/patient");
        SmartLaunchContext old = context(Instant.now().plusSeconds(60));
        SmartLaunchContext refreshed = new SmartLaunchContext(
                "eyJ.new_token", "ePatient-123", null,
                "https://fhir.epic.com/fhir/r4",
                true, "launch openid",
                Instant.now().plusSeconds(3600), "refresh_token"
        );
        setAuthentication(old);
        stubDiscovery();
        when(refreshService.refreshIfNeeded(any(), anyString(), any())).thenReturn(refreshed);

        filter.doFilter(request, response, filterChain);

        var auth = (SmartAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();
        assertThat(auth.getLaunchContext().accessToken()).isEqualTo("eyJ.new_token");
        verify(filterChain).doFilter(request, response);
    }

    // ── refresh returns null (no refresh token) ───────────────────────────────

    @Test
    void refreshReturnsNull_securityContextClearedAndSessionInvalidated() throws Exception {
        request.setRequestURI("/api/patient");
        SmartLaunchContext expiring = context(Instant.now().plusSeconds(60));
        setAuthentication(expiring);
        stubDiscovery();
        when(refreshService.refreshIfNeeded(any(), anyString(), any())).thenReturn(null);

        filter.doFilter(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(session.isInvalid()).isTrue();
        verify(filterChain).doFilter(request, response);
    }

    // ── refresh throws exception ──────────────────────────────────────────────

    @Test
    void refreshException_securityContextClearedAndSessionInvalidated() throws Exception {
        request.setRequestURI("/api/patient");
        SmartLaunchContext expiring = context(Instant.now().plusSeconds(60));
        setAuthentication(expiring);
        stubDiscovery();
        when(refreshService.refreshIfNeeded(any(), anyString(), any()))
                .thenThrow(new TokenRefreshException("Epic returned 400"));

        filter.doFilter(request, response, filterChain);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(session.isInvalid()).isTrue();
        verify(filterChain).doFilter(request, response);
    }

    // ── discovery failure ─────────────────────────────────────────────────────

    @Test
    void discoveryFailure_passesThrough_noRefreshAttempted() throws Exception {
        request.setRequestURI("/api/patient");
        SmartLaunchContext ctx = context(Instant.now().plusSeconds(60));
        setAuthentication(ctx);
        when(discoveryService.discover(anyString()))
                .thenThrow(new com.akhester.smartfhir.client.discovery.SmartDiscoveryException("unreachable"));

        filter.doFilter(request, response, filterChain);

        // Original context preserved — discovery failure is not fatal
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        verifyNoInteractions(refreshService);
        verify(filterChain).doFilter(request, response);
    }
}
