package com.akhester.smartfhir.client.auth;

import java.io.Serializable;

/**
 * A paired PKCE code_verifier / code_challenge generated for a single
 * authorization request.
 *
 * <h3>PKCE flow summary (RFC 7636)</h3>
 * <pre>
 *  1. App generates a random code_verifier (43–128 URL-safe chars).
 *  2. App computes code_challenge = BASE64URL(SHA-256(ASCII(code_verifier))).
 *  3. App sends code_challenge + code_challenge_method=S256 in the authorize URL.
 *  4. After redirect, app sends code_verifier in the token exchange POST.
 *  5. Auth server verifies SHA-256(code_verifier) == code_challenge.
 * </pre>
 *
 * The verifier is stored in the HTTP session (alongside {@link SmartLaunchSession})
 * between step 3 and step 4. The challenge is sent to Epic and never stored.
 *
 * <h3>Why Serializable?</h3>
 * Same reason as SmartLaunchSession — survives session replication to Redis.
 */
public record PkceParameters(
        String codeVerifier,
        String codeChallenge
) implements Serializable {

    // Pinned to prevent silent session invalidation during rolling deployments.
    private static final long serialVersionUID = 1L;

    /** HTTP session attribute key for the PKCE verifier. Task 5 reads this. */
    public static final String SESSION_KEY = "smart_pkce_parameters";
}
