package com.akhester.smartfhir.client.context;

import com.akhester.smartfhir.client.oidc.UserProfile;

import java.io.Serializable;
import java.time.Instant;

/**
 * Fully-resolved EHR launch context — the single object the rest of the
 * application needs after a successful SMART EHR launch.
 *
 * <h3>What this represents</h3>
 * Once the OAuth2 handshake completes (Tasks 3–5), all the information
 * needed to make FHIR API calls and render the UI is consolidated here:
 *
 * <ul>
 *   <li><b>accessToken</b>    — Bearer token for all FHIR API calls (Task 7).</li>
 *   <li><b>patientId</b>      — FHIR R4 Patient resource ID in context (e.g. {@code eD2-abc}).</li>
 *   <li><b>encounterId</b>    — FHIR R4 Encounter ID — may be {@code null} if Epic
 *                               didn't bind an encounter to this launch.</li>
 *   <li><b>fhirBaseUrl</b>    — The ISS from the original launch request — used by
 *                               Task 7's {@code FhirClientFactory} to construct the
 *                               HAPI client pointed at the right Epic server.</li>
 *   <li><b>needPatientBanner</b> — Epic UI contract: {@code true} means your app
 *                               must render a patient header; {@code false} means
 *                               Epic is already showing one (EHR-embedded apps).</li>
 *   <li><b>scope</b>          — Space-separated scopes granted. Use this to gate
 *                               features (e.g. only show medication tab if
 *                               {@code patient/MedicationRequest.rs} was granted).</li>
 *   <li><b>expiresAt</b>      — Token expiry — checked by Task 9's refresh logic.</li>
 *   <li><b>refreshToken</b>   — Used by Task 9 to obtain a new access token without
 *                               re-launching. May be {@code null} if Epic didn't
 *                               issue one (depends on scopes and client config).</li>
 * </ul>
 *
 * <h3>Lifecycle</h3>
 * Created by {@link SmartContextExtractor} from a {@link com.akhester.smartfhir.client.token.SmartTokenResponse}
 * and the original ISS. Stored in the HTTP session under {@link #SESSION_KEY}.
 * Read by controllers, services, and Task 7's {@code FhirClientFactory}.
 *
 * <h3>Why not just use SmartTokenResponse directly?</h3>
 * {@code SmartTokenResponse} is a raw JSON mapping — it lacks {@code fhirBaseUrl}
 * and has fields irrelevant to the rest of the app (token type, raw expires_in, etc.).
 * {@code SmartLaunchContext} is the application-level abstraction: only what the
 * app actually needs, in the right shape.
 */
public record SmartLaunchContext(

        String accessToken,
        String patientId,
        String encounterId,          // nullable — not all EHR launches bind an encounter
        String fhirBaseUrl,          // the ISS — FHIR server base URL for HAPI client
        boolean needPatientBanner,
        String scope,
        Instant expiresAt,
        String refreshToken,         // nullable — depends on Epic client configuration
        UserProfile userProfile      // nullable — present when openid scope was granted

) implements Serializable {

    // Bumped to 2L because userProfile field was added.
    // Any sessions serialized before this change will fail to deserialize —
    // that's acceptable: existing sessions will expire naturally, or can be
    // flushed from Redis before deploying the update.
    private static final long serialVersionUID = 2L;

    /** HTTP session attribute key — read by Task 7 and downstream controllers. */
    public static final String SESSION_KEY = "smart_launch_context";

    /**
     * Returns true if this context has an in-context encounter.
     * Use before accessing {@link #encounterId()} to avoid null checks.
     */
    public boolean hasEncounter() {
        return encounterId != null && !encounterId.isBlank();
    }

    /**
     * Returns true if the access token is expired or within {@code bufferSeconds}
     * of expiry. Task 9 uses this to decide whether to refresh proactively.
     */
    public boolean isTokenExpired(long bufferSeconds) {
        return Instant.now().isAfter(expiresAt.minusSeconds(bufferSeconds));
    }

    /** Convenience — checks expiry with a 30-second buffer. */
    public boolean isTokenExpired() {
        return isTokenExpired(30);
    }

    /**
     * Returns true if the given scope string was granted.
     * e.g. {@code context.hasScope("patient/Patient.rs")}
     */
    public boolean hasScope(String requiredScope) {
        if (scope == null || requiredScope == null) return false;
        for (String granted : scope.split("\\s+")) {
            if (granted.equals(requiredScope)) return true;
        }
        return false;
    }

    /**
     * Returns true if an OIDC user profile was validated from the id_token.
     * Requires {@code openid} scope to have been granted and the id_token
     * to have passed signature/claims validation.
     */
    public boolean hasUserProfile() {
        return userProfile != null;
    }

    /**
     * Overrides the auto-generated record toString() to mask the access token.
     * Prevents the bearer token appearing in logs, heap dumps, or debug output.
     */
    @Override
    public String toString() {
        return "SmartLaunchContext[patient=" + patientId
                + ", encounter=" + (encounterId != null ? encounterId : "(none)")
                + ", fhirBaseUrl=" + fhirBaseUrl
                + ", scope=" + scope
                + ", expiresAt=" + expiresAt
                + ", user=" + (userProfile != null ? userProfile.subject() : "(none)")
                + ", accessToken=***]";
    }
}
