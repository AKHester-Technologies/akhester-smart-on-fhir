package com.akhester.smartfhir.client.auth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for PkceHelper — verifies RFC 7636 compliance.
 *
 * Test cases:
 *  1.  Verifier length is within RFC range (43–128 chars).
 *  2.  Verifier uses only unreserved chars (URL-safe base64, no padding).
 *  3.  Challenge is a valid BASE64URL string (no +, /, or = padding).
 *  4.  Challenge length is 43 chars (32-byte SHA-256 → 43-char base64url).
 *  5.  computeChallenge(verifier) is deterministic — same input → same output.
 *  6.  generate() produces a consistent verifier/challenge pair.
 *  7.  Repeated calls produce unique verifiers (entropy check).
 *  8.  Challenge recomputed from verifier matches the generated challenge.
 */
class PkceHelperTest {

    private PkceHelper pkceHelper;

    @BeforeEach
    void setUp() {
        pkceHelper = new PkceHelper();
    }

    @Test
    void verifier_lengthWithinRfcRange() {
        PkceParameters params = pkceHelper.generate();
        int len = params.codeVerifier().length();
        // RFC 7636 §4.1: 43 ≤ length ≤ 128
        assertThat(len)
                .isGreaterThanOrEqualTo(43)
                .isLessThanOrEqualTo(128);
    }

    @Test
    void verifier_usesOnlyUnreservedChars() {
        PkceParameters params = pkceHelper.generate();
        // URL-safe base64 without padding: A-Z a-z 0-9 - _
        // RFC 7636 unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
        // Our base64url alphabet is a strict subset — valid.
        assertThat(params.codeVerifier())
                .matches("[A-Za-z0-9\\-_]+");
    }

    @Test
    void verifier_hasNoPaddingChars() {
        PkceParameters params = pkceHelper.generate();
        assertThat(params.codeVerifier()).doesNotContain("=", "+", "/");
    }

    @Test
    void challenge_isBase64UrlWithoutPadding() {
        PkceParameters params = pkceHelper.generate();
        // Base64url without padding: A-Z a-z 0-9 - _
        assertThat(params.codeChallenge())
                .matches("[A-Za-z0-9\\-_]+")
                .doesNotContain("=", "+", "/");
    }

    @Test
    void challenge_isCorrectLength() {
        PkceParameters params = pkceHelper.generate();
        // SHA-256 → 32 bytes → 43 base64url chars (without padding)
        assertThat(params.codeChallenge()).hasSize(43);
    }

    @Test
    void computeChallenge_isDeterministic() {
        String verifier = pkceHelper.generate().codeVerifier();
        String c1 = pkceHelper.computeChallenge(verifier);
        String c2 = pkceHelper.computeChallenge(verifier);
        assertThat(c1).isEqualTo(c2);
    }

    @Test
    void generatedPair_challengeMatchesVerifier() {
        // The most important test: Epic will verify SHA-256(verifier) == challenge.
        // If this fails, every token exchange will fail.
        PkceParameters params = pkceHelper.generate();
        String recomputed = pkceHelper.computeChallenge(params.codeVerifier());
        assertThat(params.codeChallenge()).isEqualTo(recomputed);
    }

    @Test
    void challenge_isValidBase64UrlDecodable() {
        PkceParameters params = pkceHelper.generate();
        // Sanity: padded form should decode to a 32-byte SHA-256 hash
        String padded = params.codeChallenge();
        // Add padding back for decoding
        while (padded.length() % 4 != 0) padded += "=";
        byte[] decoded = Base64.getUrlDecoder().decode(padded);
        assertThat(decoded).hasSize(32); // SHA-256 always 32 bytes
    }

    @RepeatedTest(10)
    void generate_producesUniqueVerifiers() {
        // Run 10 times — collect into a set and assert all are distinct.
        // Failure would indicate SecureRandom seeding problem (essentially impossible).
        Set<String> verifiers = new HashSet<>();
        for (int i = 0; i < 10; i++) {
            verifiers.add(pkceHelper.generate().codeVerifier());
        }
        assertThat(verifiers).hasSize(10);
    }
}
