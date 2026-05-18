package com.akhester.smartfhir.client.security;

import com.akhester.smartfhir.client.context.SmartContextExtractor;
import com.akhester.smartfhir.client.discovery.SmartDiscoveryService;
import com.akhester.smartfhir.client.refresh.TokenRefreshFilter;
import com.akhester.smartfhir.client.refresh.TokenRefreshService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;

/**
 * Spring Security 6 configuration for the SMART on FHIR client.
 *
 * <h3>Route security model</h3>
 * <pre>
 *   PUBLIC  (no session required):
 *     GET /launch             — Epic calls this; no session exists yet
 *     GET /callback           — Epic redirects here after authorize
 *     GET /health             — smoke test endpoint
 *     GET /actuator/health    — k8s/load balancer health probe
 *     GET /actuator/info      — optional metadata
 *
 *   AUTHENTICATED (SmartLaunchContext must exist in session):
 *     GET /api/**             — FHIR data endpoints
 *     GET /                   — app home page (post-launch redirect target)
 *     everything else         — default deny
 * </pre>
 *
 * <h3>Authentication mechanism</h3>
 * {@link SmartSecurityFilter} runs before Spring Security's own auth filters.
 * It reads {@link com.akhester.smartfhir.client.context.SmartLaunchContext} from the
 * HTTP session and, if present and non-expired, creates a
 * {@link SmartAuthenticationToken} in the {@code SecurityContext}.
 * Standard Spring Security authorization then sees the request as authenticated.
 *
 * <h3>CSRF</h3>
 * CSRF protection uses the {@link CookieCsrfTokenRepository} (Double Submit Cookie
 * pattern). This works with Epic's EHR launch because:
 * - {@code /launch} and {@code /callback} are GETs — CSRF only applies to
 *   state-mutating methods (POST, PUT, DELETE, PATCH).
 * - After authentication, AJAX calls from the frontend must include the
 *   {@code X-XSRF-TOKEN} header populated from the {@code XSRF-TOKEN} cookie.
 *
 * <h3>Session management</h3>
 * We use {@code IF_REQUIRED} — sessions are only created when needed.
 * Spring Security is told NOT to create sessions on its own for auth
 * ({@code STATELESS} would break our session-backed SMART flow).
 *
 * <h3>Why no formLogin/httpBasic?</h3>
 * The app is always launched from Epic's EHR. There is no standalone login form.
 * Any unauthenticated request to {@code /api/**} returns 401 JSON, not a
 * redirect to a login page — the {@link HttpStatusEntryPoint} handles this.
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final SmartContextExtractor contextExtractor;
    private final TokenRefreshService tokenRefreshService;
    private final SmartDiscoveryService discoveryService;

    public SecurityConfig(SmartContextExtractor contextExtractor,
                          TokenRefreshService tokenRefreshService,
                          SmartDiscoveryService discoveryService) {
        this.contextExtractor    = contextExtractor;
        this.tokenRefreshService = tokenRefreshService;
        this.discoveryService    = discoveryService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        // ── 1. SMART session filter ────────────────────────────────────────────
        // Runs before UsernamePasswordAuthenticationFilter — populates the
        // SecurityContext from the HTTP session on every request.
        http.addFilterBefore(
                new SmartSecurityFilter(contextExtractor),
                UsernamePasswordAuthenticationFilter.class);

        // ── 1b. Token refresh filter ───────────────────────────────────────────
        // Runs after SmartSecurityFilter (SecurityContext is populated) but before
        // controllers. Proactively refreshes tokens within 120s of expiry on
        // /api/** routes. shouldNotFilter() skips public routes automatically.
        http.addFilterAfter(
                new TokenRefreshFilter(tokenRefreshService, contextExtractor, discoveryService),
                SmartSecurityFilter.class);

        // ── 2. Authorization rules ─────────────────────────────────────────────
        http.authorizeHttpRequests(auth -> auth
                // Public — Epic calls these before any session exists
                .requestMatchers("/launch", "/callback").permitAll()
                // Public — health probes, smoke test, static assets
                .requestMatchers("/health", "/actuator/health", "/actuator/info").permitAll()
                .requestMatchers("/css/**", "/js/**", "/images/**", "/favicon.ico").permitAll()
                // Protected HTML pages — require a valid SMART session
                .requestMatchers("/", "/patient", "/conditions", "/medications").hasRole("SMART_USER")
                // Protected JSON API — require a valid SMART session
                .requestMatchers("/api/**").hasRole("SMART_USER")
                // Deny everything else by default
                .anyRequest().denyAll()
        );

        // ── 3. Auth entry point — 401 JSON for unauthenticated /api/** calls ───
        // Returns 401 instead of redirecting to a login page.
        // Epic-launched apps have no login page; the EHR is the identity provider.
        http.exceptionHandling(ex -> ex
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED))
        );

        // ── 4. Session management ──────────────────────────────────────────────
        // IF_REQUIRED: Spring creates sessions only when needed (not on every request).
        // We do NOT use STATELESS because our auth IS session-backed (SmartLaunchContext
        // lives in the HTTP session). STATELESS would break the entire flow.
        http.sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                // Protect against session fixation — regenerate session ID after auth.
                .sessionFixation().changeSessionId()
        );

        // ── 5. CSRF — Double Submit Cookie pattern ─────────────────────────────
        // CookieCsrfTokenRepository sets an XSRF-TOKEN cookie readable by JS.
        // httpOnly=false required so the frontend can read and replay it.
        // /launch and /callback are GETs so CSRF does not apply to them.
        CookieCsrfTokenRepository csrfRepo = CookieCsrfTokenRepository.withHttpOnlyFalse();
        CsrfTokenRequestAttributeHandler csrfHandler = new CsrfTokenRequestAttributeHandler();
        // Disable the Spring Security 6 deferred token loading to keep
        // the XSRF cookie refreshed on every response.
        csrfHandler.setCsrfRequestAttributeName(null);
        http.csrf(csrf -> csrf
                .csrfTokenRepository(csrfRepo)
                .csrfTokenRequestHandler(csrfHandler)
        );

        // ── 6. Disable unused auth mechanisms ─────────────────────────────────
        http.formLogin(form -> form.disable());
        http.httpBasic(basic -> basic.disable());

        return http.build();
    }
}
