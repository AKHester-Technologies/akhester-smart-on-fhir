package com.akhester.smartfhir.client.oidc;

import java.io.Serializable;

/**
 * Validated OIDC user profile extracted from Epic's {@code id_token}.
 *
 * <h3>What Epic puts in the id_token (when {@code openid} scope is granted)</h3>
 * <pre>
 * Header: { "alg": "RS256", "kid": "...", "typ": "JWT" }
 * Claims: {
 *   "sub":          "eProvider123",       ← Epic user FHIR ID (stable, use for identity)
 *   "iss":          "https://fhir.epic.com/...",
 *   "aud":          "your-client-id",
 *   "exp":          1234567890,
 *   "iat":          1234567000,
 *   "nonce":        "...",                ← must match what was sent in authorize request
 *   "name":         "Dr. Jane Smith",    ← if fhirUser scope granted
 *   "fhirUser":     "Practitioner/eProvider123"  ← FHIR resource reference
 * }
 * </pre>
 *
 * <h3>Why not store the raw id_token?</h3>
 * The raw JWT is validated by {@link IdTokenValidator} and then discarded.
 * Only the extracted, verified claims are kept — this prevents downstream
 * code accidentally trusting an unvalidated token string.
 *
 * <h3>Session lifecycle</h3>
 * Created by {@link IdTokenValidator} and stored in {@link com.akhester.smartfhir.client.context.SmartLaunchContext}.
 * Available for the lifetime of the authenticated session.
 * {@code null} when {@code openid} scope was not granted.
 */
public record UserProfile(

        /** OIDC subject — Epic's stable user identifier. Use this as the user's identity key. */
        String subject,

        /**
         * Display name — present when {@code fhirUser} scope is granted.
         * May be null if Epic did not include it.
         */
        String name,

        /**
         * FHIR resource reference to the authenticated user, e.g. {@code Practitioner/eXXX}.
         * Use this to read the Practitioner or Patient resource for the logged-in user.
         * Present when {@code fhirUser} scope is granted.
         */
        String fhirUser,

        /**
         * The issuer claim — must match the ISS from the launch request.
         * Validated by {@link IdTokenValidator}.
         */
        String issuer

) implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * Returns true if this profile includes a FHIR user resource reference.
     * Requires {@code fhirUser} scope to have been granted.
     */
    public boolean hasFhirUser() {
        return fhirUser != null && !fhirUser.isBlank();
    }

    /**
     * Returns a safe display name — falls back to subject if name is absent.
     */
    public String displayName() {
        return (name != null && !name.isBlank()) ? name : subject;
    }

    @Override
    public String toString() {
        // subject is an Epic internal ID — not PHI, safe to log
        return "UserProfile[subject=" + subject
                + ", fhirUser=" + (fhirUser != null ? fhirUser : "(none)")
                + ", name=" + (name != null ? "present" : "absent") + "]";
    }
}
