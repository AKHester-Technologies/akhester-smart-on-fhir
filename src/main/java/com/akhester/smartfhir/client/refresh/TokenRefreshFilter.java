package com.akhester.smartfhir.client.refresh;

import com.akhester.smartfhir.client.context.SmartContextExtractor;
import com.akhester.smartfhir.client.context.SmartLaunchContext;
import com.akhester.smartfhir.client.discovery.SmartDiscoveryService;
import com.akhester.smartfhir.client.security.SmartAuthenticationToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Per-request filter that proactively refreshes the access token on
 * authenticated requests to {@code /api/**} before it expires.
 *
 * <h3>Position in filter chain</h3>
 * Registered AFTER {@link com.akhester.smartfhir.client.security.SmartSecurityFilter}
 * (which populates the {@code SecurityContext}) and before any controller
 * is reached. Only activates if a valid {@link SmartAuthenticationToken} is
 * already in the {@code SecurityContext} — unauthenticated requests pass through
 * without any refresh attempt.
 *
 * <h3>What it does</h3>
 * <ol>
 *   <li>Checks if the current request is to a protected path ({@code /api/**}).</li>
 *   <li>Retrieves the {@link SmartLaunchContext} from the {@code SecurityContext}.</li>
 *   <li>Calls {@link TokenRefreshService#refreshIfNeeded} — which is a no-op
 *       if the token still has more than {@code REFRESH_BUFFER_SECONDS} remaining.</li>
 *   <li>If refreshed: updates the {@code SecurityContext} with the new token
 *       so the current request's FHIR calls use the fresh token.</li>
 *   <li>If refresh returns null (no refresh token): clears the {@code SecurityContext}
 *       so Spring Security returns 401 — the clinician must re-launch from Epic.</li>
 *   <li>If refresh fails: logs the error and clears the context — same 401 outcome.</li>
 * </ol>
 *
 * <h3>Why proactive refresh (not reactive)?</h3>
 * Reactive refresh (catching 401 from Epic and retrying) requires re-sending
 * the FHIR request, which means buffering the original request body and
 * rebuilding the HAPI client. Proactive refresh within a 120-second window
 * before expiry avoids all of that — the token is refreshed before the FHIR
 * call is made. The 120-second buffer also absorbs clock skew between the
 * app server and Epic's auth server.
 */
public class TokenRefreshFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(TokenRefreshFilter.class);

    private final TokenRefreshService refreshService;
    private final SmartContextExtractor contextExtractor;
    private final SmartDiscoveryService discoveryService;

    public TokenRefreshFilter(TokenRefreshService refreshService,
                               SmartContextExtractor contextExtractor,
                               SmartDiscoveryService discoveryService) {
        this.refreshService   = refreshService;
        this.contextExtractor = contextExtractor;
        this.discoveryService = discoveryService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Only refresh on API routes — skip /launch, /callback, /health etc.
        // Those routes either don't need a token or are pre-authentication.
        String path = request.getRequestURI();
        return !path.startsWith("/api/");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        var auth = SecurityContextHolder.getContext().getAuthentication();

        // Only act on authenticated SMART sessions.
        if (!(auth instanceof SmartAuthenticationToken smartAuth)) {
            filterChain.doFilter(request, response);
            return;
        }

        SmartLaunchContext current = smartAuth.getLaunchContext();
        HttpSession session = request.getSession(false);
        if (session == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // Resolve the token endpoint from discovery (cached — near-zero cost).
        String tokenEndpoint;
        try {
            tokenEndpoint = discoveryService.discover(current.fhirBaseUrl())
                    .tokenEndpoint();
        } catch (Exception e) {
            log.warn("Could not resolve token endpoint for refresh — proceeding with existing token: {}",
                    e.getMessage());
            filterChain.doFilter(request, response);
            return;
        }

        // ── Attempt proactive refresh ──────────────────────────────────────────
        SmartLaunchContext refreshed;
        try {
            refreshed = refreshService.refreshIfNeeded(current, tokenEndpoint, session);
        } catch (TokenRefreshException e) {
            log.error("Token refresh failed for patient={} — clearing session: {}",
                    current.patientId(), e.getMessage());
            SecurityContextHolder.clearContext();
            session.invalidate();
            filterChain.doFilter(request, response);
            return;
        }

        if (refreshed == null) {
            // No refresh token — cannot refresh, session is dead.
            log.warn("No refresh token for patient={} — session expired, clearing security context",
                    current.patientId());
            SecurityContextHolder.clearContext();
            session.invalidate();
            filterChain.doFilter(request, response);
            return;
        }

        // If the context was actually refreshed (new object returned), update
        // the SecurityContext so this request's FHIR calls use the new token.
        if (refreshed != current) {
            SecurityContextHolder.getContext()
                    .setAuthentication(new SmartAuthenticationToken(refreshed));
            log.debug("SecurityContext updated with refreshed token for patient={}",
                    refreshed.patientId());
        }

        filterChain.doFilter(request, response);
    }
}
