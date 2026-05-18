package com.akhester.smartfhir.client.launch;

import com.akhester.smartfhir.client.EpicProperties;
import com.akhester.smartfhir.client.auth.SmartAuthRequestBuilder;
import com.akhester.smartfhir.client.discovery.SmartConfiguration;
import com.akhester.smartfhir.client.discovery.SmartDiscoveryException;
import com.akhester.smartfhir.client.discovery.SmartDiscoveryService;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.server.ResponseStatusException;

import java.net.URI;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Step 1 of the SMART launch flow — handles both EHR launch and standalone launch.
 *
 * <h3>EHR launch (Epic sends both iss and launch)</h3>
 * <pre>
 *   GET /launch?iss=https://hospital.epic.com/.../FHIR/R4&amp;launch=abc123opaque
 * </pre>
 * Epic initiates this when a clinician clicks the app button inside Hyperspace.
 * The {@code launch} token binds the session to a specific patient and encounter.
 *
 * <h3>Standalone launch (only iss, no launch)</h3>
 * <pre>
 *   GET /launch?iss=https://hospital.epic.com/.../FHIR/R4
 * </pre>
 * The user navigates directly to the app (bookmark, patient portal link, etc.).
 * No EHR context is pre-selected — the SMART server may present a patient picker,
 * or the app must handle {@code patient} being absent from the token response.
 * The {@code launch} scope is omitted from standalone requests; {@code patient}
 * scope is included so the user can consent to patient access.
 *
 * <h3>Security notes</h3>
 * <ul>
 *   <li>This endpoint must be publicly accessible — Epic calls it before any
 *       session exists. Permitted in Task 8's SecurityConfig.</li>
 *   <li>The {@code state} nonce is 32 random bytes (256-bit entropy).</li>
 *   <li>ISS is validated with {@code URI.create()} — rejects invalid URIs and
 *       non-HTTPS schemes (except localhost for dev/test).</li>
 * </ul>
 */
@Controller
public class SmartLaunchController {

    private static final Logger log = LoggerFactory.getLogger(SmartLaunchController.class);

    /** Max age (seconds) for a pending launch session before we reject it in the callback. */
    static final long MAX_LAUNCH_AGE_SECONDS = 300; // 5 minutes

    private final SmartDiscoveryService discoveryService;
    private final EpicProperties epicProperties;
    private final SmartAuthRequestBuilder authRequestBuilder;
    private final SecureRandom secureRandom = new SecureRandom();

    public SmartLaunchController(SmartDiscoveryService discoveryService,
                                  EpicProperties epicProperties,
                                  SmartAuthRequestBuilder authRequestBuilder) {
        this.discoveryService = discoveryService;
        this.epicProperties = epicProperties;
        this.authRequestBuilder = authRequestBuilder;
    }

    /**
     * Handles both EHR launch ({@code ?iss=&launch=}) and standalone launch ({@code ?iss=} only).
     *
     * @param iss      FHIR base URL from the initiating EHR or direct URL
     * @param launch   opaque EHR context token — {@code null} for standalone launch
     * @param session  HTTP session — receives the {@link SmartLaunchSession}
     * @return redirect to the SMART authorization endpoint
     */
    @GetMapping("/launch")
    public String launch(
            @RequestParam(name = "iss") String iss,
            @RequestParam(name = "launch", required = false) String launch,
            HttpSession session) {

        // ── 1. Validate ISS ───────────────────────────────────────────────────
        validateIss(iss);

        boolean isEhrLaunch = launch != null && !launch.isBlank();

        // Log only after validation — iss is attacker-controlled until validated.
        log.info("{} launch received — iss={}",
                isEhrLaunch ? "EHR" : "Standalone", iss);

        // ── 2. Discover auth + token endpoints ────────────────────────────────
        SmartConfiguration smartConfig;
        try {
            smartConfig = discoveryService.discover(iss);
        } catch (SmartDiscoveryException ex) {
            log.error("SMART discovery failed for iss={}: {}", iss, ex.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                    "Could not retrieve SMART configuration from the EHR: " + ex.getMessage(), ex);
        }

        if (isEhrLaunch && !smartConfig.supportsEhrLaunch()) {
            log.warn("ISS {} does not advertise launch-ehr capability — proceeding anyway", iss);
        }

        // ── 3. Build scope list — differs between EHR and standalone ──────────
        // EHR launch:    includes "launch" scope → Epic injects patient/encounter context
        // Standalone:    "launch" omitted; uses "launch/patient" so user can pick a patient
        java.util.List<String> scopes;
        if (isEhrLaunch) {
            scopes = epicProperties.scopes(); // includes "launch"
        } else {
            // Strip "launch" and "fhirUser" (EHR-context-only); add "launch/patient"
            // so the auth server presents a patient picker after user login.
            scopes = new java.util.ArrayList<>(epicProperties.scopes()
                    .stream()
                    .filter(s -> !s.equals("launch") && !s.equals("fhirUser"))
                    .toList());
            if (!scopes.contains("launch/patient")) {
                scopes.add(0, "launch/patient");
            }
        }

        // ── 4. Generate state nonce ───────────────────────────────────────────
        String state = generateState();

        // ── 5. Persist launch session ─────────────────────────────────────────
        // launchToken is null for standalone — SmartAuthRequestBuilder omits the
        // launch param from the authorize URL when it is null.
        SmartLaunchSession launchSession = SmartLaunchSession.of(
                iss,
                isEhrLaunch ? launch : null,   // null signals standalone mode
                state,
                smartConfig.authorizationEndpoint(),
                smartConfig.tokenEndpoint(),
                java.util.List.copyOf(scopes)
        );
        session.setAttribute(SmartLaunchSession.SESSION_KEY, launchSession);
        log.debug("Stored {} launch session — state={}", isEhrLaunch ? "EHR" : "standalone", state);

        // ── 6. Build authorize URL (with PKCE) and redirect ───────────────────
        String authorizeUrl = authRequestBuilder.buildAuthorizeUrl(launchSession, session);

        log.info("Redirecting to authorize endpoint — mode={}, state={}",
                isEhrLaunch ? "ehr" : "standalone", state);
        return "redirect:" + authorizeUrl;
    }

    // ── private helpers ───────────────────────────────────────────────────────

    private void validateIss(String iss) {
        if (iss == null || iss.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "iss parameter is required");
        }

        URI uri;
        try {
            uri = URI.create(iss);
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "iss is not a valid URI: " + iss);
        }

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "iss must contain a valid host: " + iss);
        }

        boolean isLocalhost = "localhost".equals(host) || "127.0.0.1".equals(host);
        boolean isHttps = "https".equalsIgnoreCase(uri.getScheme());

        if (!isHttps && !isLocalhost) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "iss must use HTTPS (got scheme: " + uri.getScheme() + ")");
        }
    }

    private String generateState() {
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
