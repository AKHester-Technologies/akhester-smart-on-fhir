package com.akhester.smartfhir.client.context;

import com.akhester.smartfhir.client.oidc.IdTokenException;
import com.akhester.smartfhir.client.oidc.IdTokenValidator;
import com.akhester.smartfhir.client.oidc.UserProfile;
import com.akhester.smartfhir.client.token.SmartTokenResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Converts a raw {@link SmartTokenResponse} into a {@link SmartLaunchContext}
 * and stores it in the HTTP session.
 *
 * <h3>Responsibility</h3>
 * This is called by {@link com.akhester.smartfhir.client.token.SmartCallbackController}
 * immediately after a successful token exchange. It is the boundary between
 * "OAuth2 plumbing" and "application domain" — everything downstream works
 * with {@code SmartLaunchContext}, never with raw token responses.
 *
 * <h3>What it extracts</h3>
 * <ul>
 *   <li>{@code patient}             → {@code patientId}</li>
 *   <li>{@code encounter}           → {@code encounterId} (nullable)</li>
 *   <li>{@code need_patient_banner} → {@code needPatientBanner}</li>
 *   <li>{@code access_token}        → {@code accessToken}</li>
 *   <li>{@code scope}               → {@code scope}</li>
 *   <li>{@code expires_at}          → {@code expiresAt} (pre-computed in Task 5)</li>
 *   <li>{@code refresh_token}       → {@code refreshToken} (nullable)</li>
 *   <li>ISS from launch session     → {@code fhirBaseUrl}</li>
 * </ul>
 *
 * <h3>Session lifecycle</h3>
 * The context is stored under {@link SmartLaunchContext#SESSION_KEY} and
 * replaces (or coexists with) the raw {@link SmartTokenResponse} stored by
 * Task 5 under {@code SmartCallbackController.TOKEN_SESSION_KEY}. The raw
 * token response is removed after extraction — only {@code SmartLaunchContext}
 * remains in the session for the rest of the request lifecycle.
 */
@Component
public class SmartContextExtractor {

    private static final Logger log = LoggerFactory.getLogger(SmartContextExtractor.class);

    private final IdTokenValidator idTokenValidator;

    public SmartContextExtractor(IdTokenValidator idTokenValidator) {
        this.idTokenValidator = idTokenValidator;
    }

    /**
     * Extracts launch context from the token response and stores it in session.
     *
     * @param tokenResponse the parsed token response from Task 5
     * @param fhirBaseUrl   the ISS from the original launch (Task 3 launch session)
     * @param session       the current HTTP session
     * @return the fully-populated {@link SmartLaunchContext}
     */
    public SmartLaunchContext extract(SmartTokenResponse tokenResponse,
                                      String fhirBaseUrl,
                                      HttpSession session) {

        // ── Validate id_token and extract UserProfile ─────────────────────────
        // Attempt validation if openid scope was granted and id_token is present.
        // Failure is non-fatal — we log a warning and continue without a profile
        // rather than blocking FHIR access. The app can still function without
        // user identity; some Epic configurations omit the id_token entirely.
        UserProfile userProfile = null;
        if (tokenResponse.idToken() != null && !tokenResponse.idToken().isBlank()) {
            try {
                userProfile = idTokenValidator.validate(
                        tokenResponse.idToken(), fhirBaseUrl, null);
            } catch (IdTokenException e) {
                log.warn("id_token validation failed — proceeding without user profile: {}",
                        e.getMessage());
            }
        }

        SmartLaunchContext context = new SmartLaunchContext(
                tokenResponse.accessToken(),
                tokenResponse.patient(),
                tokenResponse.encounter(),          // nullable
                fhirBaseUrl,
                tokenResponse.needPatientBanner() != null
                        ? tokenResponse.needPatientBanner() : true,
                tokenResponse.scope(),
                tokenResponse.expiresAt(),
                tokenResponse.refreshToken(),       // nullable
                userProfile                         // nullable — null if openid not granted
        );

        // Store in session — Task 7 (FhirClientFactory) and all downstream
        // controllers read from here.
        session.setAttribute(SmartLaunchContext.SESSION_KEY, context);

        // Remove the raw token response — context is now the single source of truth.
        session.removeAttribute(com.akhester.smartfhir.client.token.SmartCallbackController.TOKEN_SESSION_KEY);

        log.info("Launch context extracted — patient={}, encounter={}, needPatientBanner={}, scopes={}",
                context.patientId(),
                context.encounterId() != null ? context.encounterId() : "(none)",
                context.needPatientBanner(),
                context.scope());

        return context;
    }

    /**
     * Retrieves the current {@link SmartLaunchContext} from the session.
     *
     * Returns {@code null} if no context is present (unauthenticated session).
     * Callers should redirect to an error page or re-launch if this returns null.
     *
     * @param session the current HTTP session
     * @return the launch context, or {@code null} if not authenticated
     */
    public SmartLaunchContext retrieve(HttpSession session) {
        Object attr = session.getAttribute(SmartLaunchContext.SESSION_KEY);
        if (attr instanceof SmartLaunchContext ctx) {
            return ctx;
        }
        return null;
    }

    /**
     * Replaces the stored context — used by Task 9 (token refresh) when a new
     * access token is obtained. Updates only the token-related fields; preserves
     * patient, encounter, and FHIR base URL.
     *
     * @param existing the current context
     * @param newToken the refreshed access token string
     * @param newExpiry the new expiry instant
     * @param session  the current HTTP session
     * @return the updated {@link SmartLaunchContext}
     */
    public SmartLaunchContext refresh(SmartLaunchContext existing,
                                      String newToken,
                                      java.time.Instant newExpiry,
                                      HttpSession session) {

        SmartLaunchContext refreshed = new SmartLaunchContext(
                newToken,
                existing.patientId(),
                existing.encounterId(),
                existing.fhirBaseUrl(),
                existing.needPatientBanner(),
                existing.scope(),
                newExpiry,
                existing.refreshToken(),
                existing.userProfile()   // user profile does not change on token refresh
        );

        session.setAttribute(SmartLaunchContext.SESSION_KEY, refreshed);
        log.info("Launch context refreshed — patient={}, newExpiry={}",
                refreshed.patientId(), refreshed.expiresAt());

        return refreshed;
    }
}
