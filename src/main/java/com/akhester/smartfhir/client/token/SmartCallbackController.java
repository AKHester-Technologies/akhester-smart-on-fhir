package com.akhester.smartfhir.client.token;

import com.akhester.smartfhir.client.auth.PkceParameters;
import com.akhester.smartfhir.client.context.SmartContextExtractor;
import com.akhester.smartfhir.client.context.SmartLaunchContext;
import com.akhester.smartfhir.client.launch.SmartLaunchController;
import com.akhester.smartfhir.client.launch.SmartLaunchSession;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

/**
 * Step 4 + 5 of the SMART EHR launch flow — Epic's redirect back to our app.
 *
 * <h3>What Epic sends</h3>
 * After the clinician approves (or Epic auto-approves for EHR launch):
 * <pre>
 *   GET /callback?code=AUTH_CODE&state=NONCE
 * </pre>
 *
 * <h3>What this controller does</h3>
 * <ol>
 *   <li><b>State validation (CSRF check)</b> — compares the {@code state} param
 *       against what was stored in session during Task 3. Rejects mismatches
 *       with 400 to prevent CSRF attacks.</li>
 *   <li><b>Session age check</b> — rejects callbacks arriving more than 5 minutes
 *       after the launch (configurable via {@code MAX_LAUNCH_AGE_SECONDS}).</li>
 *   <li><b>Error param check</b> — Epic sends {@code ?error=access_denied} if the
 *       user or EHR denies the launch. We surface this clearly rather than
 *       proceeding to a confusing token exchange failure.</li>
 *   <li><b>PKCE verifier retrieval</b> — reads the {@code code_verifier} stored
 *       in session by Task 4's {@link com.akhester.smartfhir.client.auth.SmartAuthRequestBuilder}.</li>
 *   <li><b>Token exchange</b> — calls {@link SmartTokenService} to POST the code
 *       and verifier to Epic's token endpoint.</li>
 *   <li><b>Token storage</b> — stores the {@link SmartTokenResponse} in session
 *       under {@link SmartTokenResponse#SESSION_KEY} for Tasks 6 and 7.</li>
 *   <li><b>Redirect to app home</b> — returns 302 to {@code /} so the user lands
 *       on the main application page with an authenticated session.</li>
 * </ol>
 *
 * <h3>Error handling strategy</h3>
 * All errors return a structured HTTP error (4xx or 502) rather than a redirect.
 * This keeps the failure visible in browser dev tools and avoids silent redirect
 * loops. A real app would redirect to a friendly error page instead.
 */
@Controller
public class SmartCallbackController {

    private static final Logger log = LoggerFactory.getLogger(SmartCallbackController.class);

    /** Session key for the token response — read by Tasks 6 and 7. */
    public static final String TOKEN_SESSION_KEY = "smart_token_response";

    private final SmartTokenService tokenService;
    private final SmartContextExtractor contextExtractor;

    public SmartCallbackController(SmartTokenService tokenService,
                                    SmartContextExtractor contextExtractor) {
        this.tokenService       = tokenService;
        this.contextExtractor   = contextExtractor;
    }

    /**
     * Handles Epic's authorization callback.
     *
     * @param code    authorization code from Epic (present on success)
     * @param state   CSRF nonce — must match what we stored in session
     * @param error   OAuth2 error code from Epic (present on failure)
     * @param session the current HTTP session
     * @return redirect to application home on success
     */
    @GetMapping("/callback")
    public String callback(
            @RequestParam(name = "code",  required = false) String code,
            @RequestParam(name = "state", required = false) String state,
            @RequestParam(name = "error", required = false) String error,
            @RequestParam(name = "error_description", required = false) String errorDescription,
            HttpSession session) {

        // ── 1. Check for OAuth2 error from Epic ───────────────────────────────
        if (error != null) {
            // Sanitize before logging — these values are attacker-controlled URL params.
            String safeError = error.replaceAll("[\r\n\t]", "_");
            String safeDesc  = errorDescription != null
                    ? errorDescription.replaceAll("[\r\n\t]", "_") : null;
            log.warn("OAuth2 error from Epic: {} — {}", safeError, safeDesc);
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "Authorization denied by EHR: " + safeError
                    + (safeDesc != null ? " — " + safeDesc : ""));
        }

        // ── 2. Validate required params ───────────────────────────────────────
        if (code == null || code.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Missing authorization code in callback");
        }
        if (state == null || state.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Missing state parameter in callback");
        }

        // ── 3. Retrieve and validate launch session ───────────────────────────
        SmartLaunchSession launchSession = retrieveLaunchSession(session);

        // ── 4. CSRF: verify state nonce ───────────────────────────────────────
        // Constant-time comparison isn't strictly required here (state is not
        // a MAC), but MessageDigest.isEqual avoids timing leaks on short strings.
        if (!java.security.MessageDigest.isEqual(
                state.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                launchSession.state().getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
            log.error("State mismatch — possible CSRF attack. received={}, expected={}",
                    state, launchSession.state());
            session.invalidate(); // kill the session on CSRF suspicion
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "State parameter mismatch — request may have been tampered with");
        }

        // ── 5. Reject stale sessions ──────────────────────────────────────────
        if (launchSession.isOlderThan(SmartLaunchController.MAX_LAUNCH_AGE_SECONDS)) {
            log.warn("Launch session expired — initiated={}", launchSession.initiatedAt());
            session.invalidate();
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Launch session expired — please re-launch the application from the EHR");
        }

        // ── 6. Retrieve PKCE verifier from session ────────────────────────────
        PkceParameters pkce = retrievePkceParameters(session);

        // ── 7. Exchange code for tokens ───────────────────────────────────────
        SmartTokenResponse tokenResponse;
        try {
            tokenResponse = tokenService.exchange(
                    launchSession.tokenEndpoint(),
                    code,
                    pkce.codeVerifier()
            );
        } catch (TokenExchangeException ex) {
            log.error("Token exchange failed: {}", ex.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                    "Token exchange failed: " + ex.getMessage(), ex);
        }

        // ── 8. Extract launch context and store in session (Task 6) ──────────
        // SmartContextExtractor consolidates token response + ISS into a single
        // SmartLaunchContext record, removes the raw token response, and stores
        // the context under SmartLaunchContext.SESSION_KEY.
        SmartLaunchContext context = contextExtractor.extract(
                tokenResponse, launchSession.iss(), session);

        // Clean up PKCE params — verifier served its purpose, no need to keep it.
        session.removeAttribute(PkceParameters.SESSION_KEY);

        log.info("SMART EHR launch complete — patient={}, encounter={}, scope={}",
                context.patientId(),
                context.hasEncounter() ? context.encounterId() : "(none)",
                context.scope());

        // ── 9. Redirect to app home ───────────────────────────────────────────
        return "redirect:/";
    }

    // ── private helpers ───────────────────────────────────────────────────────

    private SmartLaunchSession retrieveLaunchSession(HttpSession session) {
        Object attr = session.getAttribute(SmartLaunchSession.SESSION_KEY);
        if (attr == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "No active launch session found — did you start from /launch?");
        }
        if (!(attr instanceof SmartLaunchSession launchSession)) {
            session.invalidate();
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Corrupted launch session");
        }
        return launchSession;
    }

    private PkceParameters retrievePkceParameters(HttpSession session) {
        Object attr = session.getAttribute(PkceParameters.SESSION_KEY);
        if (attr == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "No PKCE parameters found in session — launch flow may have been interrupted");
        }
        if (!(attr instanceof PkceParameters pkce)) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR,
                    "Corrupted PKCE session data");
        }
        return pkce;
    }
}
