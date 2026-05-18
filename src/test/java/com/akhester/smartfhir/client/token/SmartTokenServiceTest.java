package com.akhester.smartfhir.client.token;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.akhester.smartfhir.client.EpicProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for SmartTokenService.
 *
 * WireMock simulates Epic's token endpoint — no real network calls.
 *
 * Test cases:
 *  1.  Happy path — 200 with full token body parsed correctly.
 *  2.  patient field extracted from token extras (not from JWT).
 *  3.  encounter field extracted (nullable).
 *  4.  expiresAt is computed from expires_in relative to now.
 *  5.  isExpired() returns false for fresh token.
 *  6.  Form body contains grant_type=authorization_code.
 *  7.  Form body contains code_verifier (PKCE).
 *  8.  Form body contains client_id and redirect_uri.
 *  9.  HTTP 400 from token endpoint → TokenExchangeException with error message.
 *  10. HTTP 401 from token endpoint → TokenExchangeException.
 *  11. Network failure → TokenExchangeException.
 *  12. Malformed JSON response → TokenExchangeException.
 *  13. Missing access_token → TokenExchangeException from validate().
 *  14. Missing patient → TokenExchangeException from validate().
 */
class SmartTokenServiceTest {

    private WireMockServer wireMock;
    private SmartTokenService tokenService;

    private static final String TOKEN_PATH     = "/oauth2/token";
    private static final String AUTH_CODE      = "authcode123";
    private static final String CODE_VERIFIER  = "verifier_abc_xyz_123";
    private static final String ACCESS_TOKEN   = "eyJhbGciOiJSUzI1NiJ9.test";
    private static final String PATIENT_ID     = "eD2-PatientABC";
    private static final String ENCOUNTER_ID   = "eE3-EncounterXYZ";

    @BeforeEach
    void setUp() {
        wireMock = new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        wireMock.start();

        EpicProperties props = new EpicProperties(
                "test-client-id",
                "http://localhost:8080/callback",
                List.of("launch", "openid", "patient/Patient.rs"),
                60
        );
        tokenService = new SmartTokenService(props, new ObjectMapper());
    }

    @AfterEach
    void tearDown() {
        wireMock.stop();
    }

    private String tokenEndpoint() {
        return "http://localhost:" + wireMock.port() + TOKEN_PATH;
    }

    private String fullTokenJson() {
        return """
                {
                  "access_token":        "%s",
                  "token_type":          "Bearer",
                  "expires_in":          3600,
                  "refresh_token":       "refresh_abc",
                  "scope":               "launch openid patient/Patient.rs",
                  "patient":             "%s",
                  "encounter":           "%s",
                  "need_patient_banner": true,
                  "id_token":            "eyJoZWFkZXJ9.eyJzdWIiOiJ1c2VyIn0.sig"
                }
                """.formatted(ACCESS_TOKEN, PATIENT_ID, ENCOUNTER_ID);
    }

    private void stubToken(int status, String body) {
        wireMock.stubFor(post(urlEqualTo(TOKEN_PATH))
                .willReturn(aResponse()
                        .withStatus(status)
                        .withHeader("Content-Type", "application/json")
                        .withBody(body)));
    }

    // ── happy path ────────────────────────────────────────────────────────────

    @Test
    void happyPath_parsesAccessToken() {
        stubToken(200, fullTokenJson());
        SmartTokenResponse resp = tokenService.exchange(tokenEndpoint(), AUTH_CODE, CODE_VERIFIER);
        assertThat(resp.accessToken()).isEqualTo(ACCESS_TOKEN);
    }

    @Test
    void happyPath_parsesPatientFromExtras() {
        stubToken(200, fullTokenJson());
        SmartTokenResponse resp = tokenService.exchange(tokenEndpoint(), AUTH_CODE, CODE_VERIFIER);
        // patient is a top-level field in the token response body, not in the JWT
        assertThat(resp.patient()).isEqualTo(PATIENT_ID);
    }

    @Test
    void happyPath_parsesEncounterFromExtras() {
        stubToken(200, fullTokenJson());
        SmartTokenResponse resp = tokenService.exchange(tokenEndpoint(), AUTH_CODE, CODE_VERIFIER);
        assertThat(resp.encounter()).isEqualTo(ENCOUNTER_ID);
    }

    @Test
    void happyPath_parsesNeedPatientBanner() {
        stubToken(200, fullTokenJson());
        SmartTokenResponse resp = tokenService.exchange(tokenEndpoint(), AUTH_CODE, CODE_VERIFIER);
        assertThat(resp.needPatientBanner()).isTrue();
    }

    @Test
    void happyPath_expiresAtComputedFromExpiresIn() {
        stubToken(200, fullTokenJson());

        // Capture wall-clock BEFORE the call so the tolerance window is pinned
        // to when exchange() ran, not when the assertion runs.
        // Without this, a slow CI machine can push the assertion outside the window.
        java.time.Instant before = java.time.Instant.now();
        SmartTokenResponse resp = tokenService.exchange(tokenEndpoint(), AUTH_CODE, CODE_VERIFIER);

        assertThat(resp.expiresAt()).isNotNull();
        assertThat(resp.expiresAt().getEpochSecond())
                .isBetween(
                        before.plusSeconds(3595).getEpochSecond(),
                        before.plusSeconds(3605).getEpochSecond()
                );
    }

    @Test
    void happyPath_freshTokenIsNotExpired() {
        stubToken(200, fullTokenJson());
        SmartTokenResponse resp = tokenService.exchange(tokenEndpoint(), AUTH_CODE, CODE_VERIFIER);
        assertThat(resp.isExpired()).isFalse();
    }

    // ── form body assertions ──────────────────────────────────────────────────

    @Test
    void request_containsGrantTypeAuthorizationCode() {
        stubToken(200, fullTokenJson());
        tokenService.exchange(tokenEndpoint(), AUTH_CODE, CODE_VERIFIER);

        wireMock.verify(postRequestedFor(urlEqualTo(TOKEN_PATH))
                .withRequestBody(containing("grant_type=authorization_code")));
    }

    @Test
    void request_containsCodeVerifierForPkce() {
        stubToken(200, fullTokenJson());
        tokenService.exchange(tokenEndpoint(), AUTH_CODE, CODE_VERIFIER);

        wireMock.verify(postRequestedFor(urlEqualTo(TOKEN_PATH))
                .withRequestBody(containing("code_verifier=" + CODE_VERIFIER)));
    }

    @Test
    void request_containsClientIdAndRedirectUri() {
        stubToken(200, fullTokenJson());
        tokenService.exchange(tokenEndpoint(), AUTH_CODE, CODE_VERIFIER);

        wireMock.verify(postRequestedFor(urlEqualTo(TOKEN_PATH))
                .withRequestBody(containing("client_id=test-client-id"))
                .withRequestBody(containing("redirect_uri=")));
    }

    // ── error handling ────────────────────────────────────────────────────────

    @Test
    void http400_throwsTokenExchangeException() {
        stubToken(400, """
                {"error":"invalid_grant","error_description":"Authorization code expired"}
                """);

        assertThatThrownBy(() ->
                tokenService.exchange(tokenEndpoint(), AUTH_CODE, CODE_VERIFIER))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("400");
    }

    @Test
    void http401_throwsTokenExchangeException() {
        stubToken(401, """
                {"error":"invalid_client"}
                """);

        assertThatThrownBy(() ->
                tokenService.exchange(tokenEndpoint(), AUTH_CODE, CODE_VERIFIER))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("401");
    }

    @Test
    void malformedJson_throwsTokenExchangeException() {
        stubToken(200, "not valid json {{{");

        assertThatThrownBy(() ->
                tokenService.exchange(tokenEndpoint(), AUTH_CODE, CODE_VERIFIER))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("parse");
    }

    @Test
    void missingAccessToken_throwsTokenExchangeException() {
        stubToken(200, """
                {
                  "token_type": "Bearer",
                  "expires_in": 3600,
                  "patient": "%s"
                }
                """.formatted(PATIENT_ID));

        assertThatThrownBy(() ->
                tokenService.exchange(tokenEndpoint(), AUTH_CODE, CODE_VERIFIER))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("access_token");
    }

    @Test
    void missingPatient_throwsTokenExchangeException() {
        // Epic always includes patient for EHR launch — missing it means
        // the scopes were wrong or the launch context was lost.
        stubToken(200, """
                {
                  "access_token": "eyJ.test",
                  "token_type":   "Bearer",
                  "expires_in":   3600
                }
                """);

        assertThatThrownBy(() ->
                tokenService.exchange(tokenEndpoint(), AUTH_CODE, CODE_VERIFIER))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("patient");
    }

    @Test
    void nullTokenEndpoint_throwsTokenExchangeException() {
        // URI.create(null) would throw NullPointerException with no useful message.
        // The guard converts this to a clear TokenExchangeException.
        assertThatThrownBy(() ->
                tokenService.exchange(null, AUTH_CODE, CODE_VERIFIER))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("tokenEndpoint");
    }

    @Test
    void blankTokenEndpoint_throwsTokenExchangeException() {
        assertThatThrownBy(() ->
                tokenService.exchange("   ", AUTH_CODE, CODE_VERIFIER))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("tokenEndpoint");
    }
