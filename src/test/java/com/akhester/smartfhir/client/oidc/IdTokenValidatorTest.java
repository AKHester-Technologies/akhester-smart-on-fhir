package com.akhester.smartfhir.client.oidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.akhester.smartfhir.client.EpicProperties;
import com.akhester.smartfhir.client.discovery.SmartConfiguration;
import com.akhester.smartfhir.client.discovery.SmartDiscoveryService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * Unit tests for IdTokenValidator.
 *
 * We build minimal JWT strings manually (base64url-encoded JSON parts)
 * so we can precisely control each claim without a real key/signer.
 * The signature part is set to "fakesig" — the validator's structural
 * checks are tested; cryptographic verification is documented as a TODO.
 *
 * Test cases:
 *  1.  Valid token — returns UserProfile with correct claims.
 *  2.  subject extracted correctly.
 *  3.  name extracted when present.
 *  4.  fhirUser extracted when present.
 *  5.  null name — UserProfile.displayName() falls back to subject.
 *  6.  Wrong algorithm (ES256) — throws IdTokenException.
 *  7.  Wrong issuer — throws IdTokenException.
 *  8.  Wrong audience — throws IdTokenException.
 *  9.  Expired token — throws IdTokenException.
 *  10. Nonce mismatch — throws IdTokenException.
 *  11. Missing sub claim — throws IdTokenException.
 *  12. Missing iss claim — throws IdTokenException.
 *  13. Missing exp claim — throws IdTokenException.
 *  14. Not a JWT (malformed) — throws IdTokenException.
 *  15. Null id_token — throws IdTokenException.
 */
@ExtendWith(MockitoExtension.class)
class IdTokenValidatorTest {

    @Mock SmartDiscoveryService discoveryService;

    private IdTokenValidator validator;

    private static final String ISS       = "https://fhir.epic.com/interconnect-fhir-oauth";
    private static final String CLIENT_ID = "test-client-id";
    private static final String SUBJECT   = "eProvider-ABC123";
    private static final String NONCE     = "test-nonce-xyz";

    @BeforeEach
    void setUp() {
        EpicProperties props = new EpicProperties(
                CLIENT_ID, "http://localhost:8080/callback",
                List.of("launch", "openid"), 60);

        // Stub discovery to return a config with a token endpoint
        SmartConfiguration config = new SmartConfiguration(
                ISS + "/oauth2/authorize",
                ISS + "/oauth2/token",
                null, null, null,
                List.of("launch-ehr"), List.of("S256")
        );
        when(discoveryService.discover(anyString())).thenReturn(config);

        validator = new IdTokenValidator(props, discoveryService, new ObjectMapper());
    }

    // ── JWT builder helpers ───────────────────────────────────────────────────

    private String b64(String json) {
        return Base64.getUrlEncoder().withoutPadding()
                .encodeToString(json.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private String buildToken(String headerJson, String payloadJson) {
        return b64(headerJson) + "." + b64(payloadJson) + ".fakesig";
    }

    private String validHeader() {
        return "{\"alg\":\"RS256\",\"kid\":\"key1\",\"typ\":\"JWT\"}";
    }

    private String validPayload(long expOffset, String nonce,
                                String name, String fhirUser) {
        long exp = Instant.now().plusSeconds(expOffset).getEpochSecond();
        return "{\"sub\":\"" + SUBJECT + "\""
                + ",\"iss\":\"" + ISS + "\""
                + ",\"aud\":\"" + CLIENT_ID + "\""
                + ",\"exp\":" + exp
                + (nonce != null ? ",\"nonce\":\"" + nonce + "\"" : "")
                + (name != null ? ",\"name\":\"" + name + "\"" : "")
                + (fhirUser != null ? ",\"fhirUser\":\"" + fhirUser + "\"" : "")
                + "}";
    }

    private String validToken() {
        return buildToken(validHeader(),
                validPayload(3600, null, "Dr. Jane Smith",
                        "Practitioner/eProvider-ABC123"));
    }

    // ── happy path ────────────────────────────────────────────────────────────

    @Test
    void validToken_returnsUserProfile() {
        UserProfile profile = validator.validate(validToken(), ISS, null);
        assertThat(profile).isNotNull();
    }

    @Test
    void validToken_extractsSubject() {
        UserProfile profile = validator.validate(validToken(), ISS, null);
        assertThat(profile.subject()).isEqualTo(SUBJECT);
    }

    @Test
    void validToken_extractsName() {
        UserProfile profile = validator.validate(validToken(), ISS, null);
        assertThat(profile.name()).isEqualTo("Dr. Jane Smith");
    }

    @Test
    void validToken_extractsFhirUser() {
        UserProfile profile = validator.validate(validToken(), ISS, null);
        assertThat(profile.fhirUser()).isEqualTo("Practitioner/eProvider-ABC123");
        assertThat(profile.hasFhirUser()).isTrue();
    }

    @Test
    void noName_displayNameFallsBackToSubject() {
        String token = buildToken(validHeader(),
                validPayload(3600, null, null, null));
        UserProfile profile = validator.validate(token, ISS, null);
        assertThat(profile.displayName()).isEqualTo(SUBJECT);
    }

    @Test
    void validNonce_passes() {
        String token = buildToken(validHeader(),
                validPayload(3600, NONCE, "Dr. Smith", null));
        assertThatNoException().isThrownBy(() ->
                validator.validate(token, ISS, NONCE));
    }

    // ── validation failures ───────────────────────────────────────────────────

    @Test
    void wrongAlgorithm_throwsIdTokenException() {
        String token = buildToken(
                "{\"alg\":\"ES256\",\"kid\":\"k1\",\"typ\":\"JWT\"}",
                validPayload(3600, null, null, null));

        assertThatThrownBy(() -> validator.validate(token, ISS, null))
                .isInstanceOf(IdTokenException.class)
                .hasMessageContaining("ES256");
    }

    @Test
    void wrongIssuer_throwsIdTokenException() {
        String payload = "{\"sub\":\"" + SUBJECT + "\""
                + ",\"iss\":\"https://evil.com\""
                + ",\"aud\":\"" + CLIENT_ID + "\""
                + ",\"exp\":" + Instant.now().plusSeconds(3600).getEpochSecond()
                + "}";
        String token = buildToken(validHeader(), payload);

        assertThatThrownBy(() -> validator.validate(token, ISS, null))
                .isInstanceOf(IdTokenException.class)
                .hasMessageContaining("iss mismatch");
    }

    @Test
    void wrongAudience_throwsIdTokenException() {
        String payload = "{\"sub\":\"" + SUBJECT + "\""
                + ",\"iss\":\"" + ISS + "\""
                + ",\"aud\":\"wrong-client-id\""
                + ",\"exp\":" + Instant.now().plusSeconds(3600).getEpochSecond()
                + "}";
        String token = buildToken(validHeader(), payload);

        assertThatThrownBy(() -> validator.validate(token, ISS, null))
                .isInstanceOf(IdTokenException.class)
                .hasMessageContaining("aud");
    }

    @Test
    void expiredToken_throwsIdTokenException() {
        String token = buildToken(validHeader(),
                validPayload(-100, null, null, null)); // expired 100s ago

        assertThatThrownBy(() -> validator.validate(token, ISS, null))
                .isInstanceOf(IdTokenException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void nonceMismatch_throwsIdTokenException() {
        String token = buildToken(validHeader(),
                validPayload(3600, "wrong-nonce", null, null));

        assertThatThrownBy(() -> validator.validate(token, ISS, NONCE))
                .isInstanceOf(IdTokenException.class)
                .hasMessageContaining("nonce");
    }

    @Test
    void missingSubject_throwsIdTokenException() {
        String payload = "{\"iss\":\"" + ISS + "\""
                + ",\"aud\":\"" + CLIENT_ID + "\""
                + ",\"exp\":" + Instant.now().plusSeconds(3600).getEpochSecond()
                + "}";
        String token = buildToken(validHeader(), payload);

        assertThatThrownBy(() -> validator.validate(token, ISS, null))
                .isInstanceOf(IdTokenException.class)
                .hasMessageContaining("sub");
    }

    @Test
    void missingIss_throwsIdTokenException() {
        String payload = "{\"sub\":\"" + SUBJECT + "\""
                + ",\"aud\":\"" + CLIENT_ID + "\""
                + ",\"exp\":" + Instant.now().plusSeconds(3600).getEpochSecond()
                + "}";
        String token = buildToken(validHeader(), payload);

        assertThatThrownBy(() -> validator.validate(token, ISS, null))
                .isInstanceOf(IdTokenException.class)
                .hasMessageContaining("iss");
    }

    @Test
    void missingExp_throwsIdTokenException() {
        String payload = "{\"sub\":\"" + SUBJECT + "\""
                + ",\"iss\":\"" + ISS + "\""
                + ",\"aud\":\"" + CLIENT_ID + "\""
                + "}";
        String token = buildToken(validHeader(), payload);

        assertThatThrownBy(() -> validator.validate(token, ISS, null))
                .isInstanceOf(IdTokenException.class)
                .hasMessageContaining("exp");
    }

    @Test
    void malformedJwt_throwsIdTokenException() {
        assertThatThrownBy(() ->
                validator.validate("not.a.jwt.at.all.extra.dots", ISS, null))
                .isInstanceOf(IdTokenException.class);
    }

    @Test
    void nullIdToken_throwsIdTokenException() {
        assertThatThrownBy(() -> validator.validate(null, ISS, null))
                .isInstanceOf(IdTokenException.class);
    }
}
