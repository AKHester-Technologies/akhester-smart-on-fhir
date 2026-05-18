package com.akhester.smartfhir.client.auth;

import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Generates PKCE parameters per RFC 7636 §4.
 *
 * <h3>Verifier spec (§4.1)</h3>
 * <pre>
 *   code_verifier = 43*128unreserved
 *   unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
 * </pre>
 * We use 96 random bytes → 128 URL-safe base64 chars (no padding).
 * This is within the 43–128 range and gives 768 bits of entropy — well
 * above the 256-bit minimum recommended by the spec.
 *
 * <h3>Challenge spec (§4.2)</h3>
 * <pre>
 *   code_challenge = BASE64URL(SHA256(ASCII(code_verifier)))
 * </pre>
 * Epic requires {@code code_challenge_method=S256}. Plain method is not
 * accepted by Epic and considered insecure (no hashing = verifier exposed
 * in the browser's network log).
 *
 * <h3>Thread safety</h3>
 * {@link SecureRandom} is thread-safe. {@link MessageDigest} is not, so
 * we call {@code MessageDigest.getInstance()} per call (cheap — it clones
 * a cached prototype internally in modern JDKs).
 */
@Component
public class PkceHelper {

    /** Number of random bytes for the verifier — yields a 128-char base64 string. */
    private static final int VERIFIER_BYTE_LENGTH = 96;

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generates a fresh {@link PkceParameters} pair.
     *
     * @return a new verifier/challenge pair; never null
     * @throws IllegalStateException if SHA-256 is unavailable (never in practice
     *                               on any compliant JRE)
     */
    public PkceParameters generate() {
        String verifier  = generateVerifier();
        String challenge = computeChallenge(verifier);
        return new PkceParameters(verifier, challenge);
    }

    /**
     * Recomputes the S256 challenge for a given verifier.
     * Used in tests to verify that generate() produces consistent pairs.
     */
    public String computeChallenge(String verifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(verifier.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is required by Java SE spec — this cannot happen
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    // ── private ───────────────────────────────────────────────────────────────

    private String generateVerifier() {
        byte[] bytes = new byte[VERIFIER_BYTE_LENGTH];
        secureRandom.nextBytes(bytes);
        // URL-safe base64 without padding satisfies the unreserved-char requirement
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
