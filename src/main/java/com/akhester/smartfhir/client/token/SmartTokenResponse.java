package com.akhester.smartfhir.client.token;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;

/**
 * Parsed response from Epic's token endpoint.
 *
 * <h3>Standard OAuth2 fields</h3>
 * {@code access_token}, {@code token_type}, {@code expires_in},
 * {@code refresh_token}, {@code scope} — present in all OAuth2 responses.
 *
 * <h3>SMART on FHIR extras (Epic-specific)</h3>
 * Epic includes additional fields in the token response that carry EHR context.
 * These are NOT in the access token JWT — they are top-level JSON fields
 * alongside {@code access_token}:
 *
 * <pre>
 * {
 *   "access_token":        "eyJ...",
 *   "token_type":          "Bearer",
 *   "expires_in":          3600,
 *   "scope":               "launch openid patient/Patient.rs",
 *   "patient":             "eD2-abc123",       ← FHIR Patient ID
 *   "encounter":           "eE3-xyz789",       ← FHIR Encounter ID (if present)
 *   "need_patient_banner": true,               ← show patient header in UI?
 *   "smart_style_url":     "https://...",      ← Epic UI theme (optional)
 *   "id_token":            "eyJ..."            ← OpenID Connect (if openid scope)
 * }
 * </pre>
 *
 * {@code @JsonIgnoreProperties(ignoreUnknown = true)} — Epic regularly adds
 * new fields; we must not fail deserialization when they appear.
 *
 * {@code expiresAt} is derived (not deserialized) — computed from
 * {@code expires_in} at parse time so callers don't have to track wall-clock.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SmartTokenResponse(

        // ── Standard OAuth2 ──────────────────────────────────────────────────
        @JsonProperty("access_token")
        String accessToken,

        @JsonProperty("token_type")
        String tokenType,

        @JsonProperty("expires_in")
        long expiresIn,

        @JsonProperty("refresh_token")
        String refreshToken,

        @JsonProperty("scope")
        String scope,

        @JsonProperty("id_token")
        String idToken,

        // ── SMART on FHIR extras (Epic populates these) ──────────────────────
        @JsonProperty("patient")
        String patient,           // FHIR R4 Patient resource ID — primary context

        @JsonProperty("encounter")
        String encounter,         // FHIR R4 Encounter ID — may be null

        @JsonProperty("need_patient_banner")
        Boolean needPatientBanner, // Boxed — null when absent; default true in SmartContextExtractor

        @JsonProperty("smart_style_url")
        String smartStyleUrl,     // Epic theme URL — optional, rarely used

        // ── Derived (not from JSON) ──────────────────────────────────────────
        // @JsonIgnore prevents Jackson attempting to deserialize this field if
        // Epic ever adds an "expiresAt" field to their token response.
        @JsonIgnore
        Instant expiresAt         // computed: Instant.now() + expires_in seconds

) {

    /**
     * Returns true if the access token has expired (or expires within
     * the given buffer of seconds). Use a buffer (e.g. 30s) to account
     * for clock skew between the app server and Epic's auth server.
     */
    public boolean isExpired(long bufferSeconds) {
        return Instant.now().isAfter(expiresAt.minusSeconds(bufferSeconds));
    }

    /** Convenience — checks expiry with a 30-second buffer. */
    public boolean isExpired() {
        return isExpired(30);
    }

    /**
     * Factory method that computes {@code expiresAt} from the raw JSON fields.
     * Called by {@link SmartTokenService} after deserialization.
     */
    public static SmartTokenResponse withComputedExpiry(SmartTokenResponse raw) {
        Instant expiresAt = Instant.now().plusSeconds(raw.expiresIn());
        return new SmartTokenResponse(
                raw.accessToken(), raw.tokenType(), raw.expiresIn(),
                raw.refreshToken(), raw.scope(), raw.idToken(),
                raw.patient(), raw.encounter(), raw.needPatientBanner(),
                raw.smartStyleUrl(), expiresAt
        );
    }

    /**
     * Validates that the minimum required fields are present.
     * Called immediately after token exchange.
     *
     * <h3>Standalone launch note</h3>
     * For standalone launch, {@code patient} may be absent from the token response —
     * the user hasn't selected a patient yet (or the auth server doesn't pre-select one).
     * In that case {@code patient} will be null in the resulting {@link com.akhester.smartfhir.client.context.SmartLaunchContext}.
     * {@code PatientDataController} handles this via scope gating.
     */
    public void validate() {
        if (accessToken == null || accessToken.isBlank()) {
            throw new TokenExchangeException("Token response missing access_token");
        }
        // patient may be null for standalone launch — not a validation failure
        // EHR launch: patient is always present (validated by Epic when launch scope used)
    }
}
