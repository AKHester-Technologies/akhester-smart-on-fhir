package com.akhester.smartfhir.client.security;

import com.akhester.smartfhir.client.context.SmartContextExtractor;
import com.akhester.smartfhir.client.context.SmartLaunchContext;
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
 * Per-request filter that bridges the SMART session (HTTP session attribute)
 * into Spring Security's {@code SecurityContext}.
 *
 * <h3>What it does on every request</h3>
 * <ol>
 *   <li>Reads the {@link SmartLaunchContext} from the HTTP session via
 *       {@link SmartContextExtractor#retrieve(HttpSession)}.</li>
 *   <li>If a context is present and the token is not expired, creates a
 *       {@link SmartAuthenticationToken} and sets it into
 *       {@code SecurityContextHolder}. The rest of the request proceeds
 *       as an authenticated SMART user.</li>
 *   <li>If no context is present, or the token is expired, the security
 *       context is left empty — Spring Security's own filter chain handles
 *       the 401 response for protected routes.</li>
 * </ol>
 *
 * <h3>Why not use Spring Security's session management?</h3>
 * Spring Security's default session-based auth stores its own
 * {@code SecurityContext} in the session. Our context is a {@link SmartLaunchContext},
 * not a Spring {@code SecurityContext} — they are stored under different keys.
 * This filter re-creates the {@code Authentication} from our context on each
 * request rather than deserializing Spring's own security context, which keeps
 * the two concerns cleanly separated.
 *
 * <h3>Position in filter chain</h3>
 * Registered before {@code UsernamePasswordAuthenticationFilter} in
 * {@link SecurityConfig}. This ensures the {@code SecurityContext} is populated
 * before any authorization decisions are made.
 */
public class SmartSecurityFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(SmartSecurityFilter.class);

    private final SmartContextExtractor contextExtractor;

    public SmartSecurityFilter(SmartContextExtractor contextExtractor) {
        this.contextExtractor = contextExtractor;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        HttpSession session = request.getSession(false); // false = don't create session
        if (session != null) {
            SmartLaunchContext context = contextExtractor.retrieve(session);

            if (context != null && !context.isTokenExpired()) {
                // Valid SMART session — populate the SecurityContext.
                SmartAuthenticationToken auth = new SmartAuthenticationToken(context);
                SecurityContextHolder.getContext().setAuthentication(auth);
                log.debug("SMART auth set for patient={} on {}",
                        context.patientId(), request.getRequestURI());

            } else if (context != null && context.isTokenExpired()) {
                // Expired token — clear any stale security context.
                // PatientDataController.requireContext() will return 401.
                SecurityContextHolder.clearContext();
                log.debug("Expired SMART session on {} — cleared security context",
                        request.getRequestURI());
            }
        }

        filterChain.doFilter(request, response);
    }
}
