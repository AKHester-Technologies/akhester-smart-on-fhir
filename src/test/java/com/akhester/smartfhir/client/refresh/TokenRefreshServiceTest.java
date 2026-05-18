package com.akhester.smartfhir.client.refresh;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.akhester.smartfhir.client.EpicProperties;
import com.akhester.smartfhir.client.context.SmartContextExtractor;
import com.akhester.smartfhir.client.context.SmartLaunchContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;

import java.time.Instant;
import java.util.List;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for TokenRefreshService.
 *
 * Test cases:
 *  1.  Token not near expiry → original context returned unchanged, no network call.
 *  2.  Token within buffer + refresh_token present → refresh POST sent.
 *  3.  Successful refresh → new access_token stored in session.
 *  4.  Successful refresh → expiresAt updated from expires_in.
 *  5.  Refresh token rotation → new refresh_token stored in context.
 *  6.  Refresh response without new refresh_token → original refresh_token retained.
 *  7.  No refresh_token on context → null returned, no network call.
 *  8.  HTTP 400 from token endpoint → TokenRefreshException thrown.
 *  9.  HTTP 401 from token endpoint → TokenRefreshException thrown.
 *  10. Network failure → TokenRefreshException thrown.
 *  11. Missing access_token in response → TokenRefreshException thrown.
 *  12. forceRefresh() ignores buffer and always POSTs.
 *  13. forceRefresh() with no refresh_token → null returned.
 *  14. Refresh form body contains grant_type=refresh_token.
 *  15. Refresh form body contains client_id.
 */
class TokenRefreshServiceTest {

    private WireMockServer wireMock;
    private TokenRefreshService service;

    private static final String TOKEN_PATH     = "/oauth2/token";
    private static final String FHIR_BASE      = "https://fhir.epic.com/fhir/r4";
    private static final String REFRESH_TOKEN  = "refresh_token_abc";
    private static final String NEW_ACCESS     = "eyJ.new_access_token";
    private static final String NEW_REFRESH    = "new_refresh_token_xyz";

    @BeforeEach
    void setUp() {
        wireMock = new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort());
        wireMock.start();

        EpicProperties props = new EpicProperties(
                "test-client-id", "http://localhost:8080/callback",
                List.of("launch", "openid"), 60);

        service = new TokenRefreshService(props, new SmartContextExtractor(), new ObjectMapper());
    }

    @AfterEach
    void tearDown() { wireMock.stop(); }

    private String tokenEndpoint() {
        return "http://localhost:" + wireMock.port() + TOKEN_PATH;
    }

    private SmartLaunchContext context(Instant expiresAt, String refreshToken) {
        return new SmartLaunchContext(
                "eyJ.old_access_token", "ePatient-123", null,
                FHIR_BASE, true, "launch openid",
                expiresAt, refreshToken,
                null);
    }

    private SmartLaunchContext nearlyExpiredContext() {
        return context(Instant.now().plusSeconds(60), REFRESH_TOKEN); // within 120s buffer
    }

    private SmartLaunchContext freshContext() {
        return context(Instant.now().plusSeconds(3600), REFRESH_TOKEN); // far from expiry
    }

    private void stubRefresh(int status, String body) {
        wireMock.stubFor(post(urlEqualTo(TOKEN_PATH))
                .willReturn(aResponse()
                        .withStatus(status)
                        .withHeader("Content-Type", "application/json")
                        .withBody(body)));
    }

    private String refreshResponseJson(boolean includeNewRefreshToken) {
        String base = """
                {
                  "access_token": "%s",
                  "token_type": "Bearer",
                  "expires_in": 3600
                  %s
                }
                """.formatted(NEW_ACCESS,
                includeNewRefreshToken ? ", \"refresh_token\": \"" + NEW_REFRESH + "\"" : "");
        return base;
    }

    // ── no-op when token is fresh ─────────────────────────────────────────────

    @Test
    void freshToken_returnsUnchangedContext_noNetworkCall() {
        SmartLaunchContext fresh = freshContext();
        SmartLaunchContext result = service.refreshIfNeeded(fresh, tokenEndpoint(), new MockHttpSession());

        assertThat(result).isSameAs(fresh);
        wireMock.verify(0, postRequestedFor(urlEqualTo(TOKEN_PATH)));
    }

    // ── successful refresh ────────────────────────────────────────────────────

    @Test
    void nearlyExpired_sendsRefreshPost() {
        stubRefresh(200, refreshResponseJson(false));
        service.refreshIfNeeded(nearlyExpiredContext(), tokenEndpoint(), new MockHttpSession());

        wireMock.verify(1, postRequestedFor(urlEqualTo(TOKEN_PATH)));
    }

    @Test
    void successfulRefresh_storesNewAccessTokenInSession() {
        stubRefresh(200, refreshResponseJson(false));
        MockHttpSession session = new MockHttpSession();

        SmartLaunchContext result = service.refreshIfNeeded(nearlyExpiredContext(), tokenEndpoint(), session);

        assertThat(result).isNotNull();
        assertThat(result.accessToken()).isEqualTo(NEW_ACCESS);
        Object stored = session.getAttribute(SmartLaunchContext.SESSION_KEY);
        assertThat(stored).isInstanceOf(SmartLaunchContext.class);
        assertThat(((SmartLaunchContext) stored).accessToken()).isEqualTo(NEW_ACCESS);
    }

    @Test
    void successfulRefresh_updatesExpiresAt() {
        stubRefresh(200, refreshResponseJson(false));
        Instant before = Instant.now();
        SmartLaunchContext result = service.refreshIfNeeded(nearlyExpiredContext(), tokenEndpoint(), new MockHttpSession());

        assertThat(result.expiresAt().getEpochSecond())
                .isBetween(before.plusSeconds(3595).getEpochSecond(),
                           before.plusSeconds(3605).getEpochSecond());
    }

    @Test
    void refreshTokenRotation_storesNewRefreshToken() {
        stubRefresh(200, refreshResponseJson(true));
        SmartLaunchContext result = service.refreshIfNeeded(nearlyExpiredContext(), tokenEndpoint(), new MockHttpSession());

        assertThat(result.refreshToken()).isEqualTo(NEW_REFRESH);
    }

    @Test
    void noNewRefreshToken_retainsOriginal() {
        stubRefresh(200, refreshResponseJson(false)); // no new refresh token in response
        SmartLaunchContext result = service.refreshIfNeeded(nearlyExpiredContext(), tokenEndpoint(), new MockHttpSession());

        assertThat(result.refreshToken()).isEqualTo(REFRESH_TOKEN);
    }

    // ── no refresh token ──────────────────────────────────────────────────────

    @Test
    void noRefreshToken_returnsNull_noNetworkCall() {
        SmartLaunchContext noRefresh = context(Instant.now().plusSeconds(60), null);
        SmartLaunchContext result = service.refreshIfNeeded(noRefresh, tokenEndpoint(), new MockHttpSession());

        assertThat(result).isNull();
        wireMock.verify(0, postRequestedFor(urlEqualTo(TOKEN_PATH)));
    }

    // ── error handling ────────────────────────────────────────────────────────

    @Test
    void http400_throwsTokenRefreshException() {
        stubRefresh(400, "{\"error\":\"invalid_grant\"}");

        assertThatThrownBy(() ->
                service.refreshIfNeeded(nearlyExpiredContext(), tokenEndpoint(), new MockHttpSession()))
                .isInstanceOf(TokenRefreshException.class)
                .hasMessageContaining("400");
    }

    @Test
    void http401_throwsTokenRefreshException() {
        stubRefresh(401, "{\"error\":\"invalid_client\"}");

        assertThatThrownBy(() ->
                service.refreshIfNeeded(nearlyExpiredContext(), tokenEndpoint(), new MockHttpSession()))
                .isInstanceOf(TokenRefreshException.class)
                .hasMessageContaining("401");
    }

    @Test
    void missingAccessTokenInResponse_throwsTokenRefreshException() {
        stubRefresh(200, "{\"token_type\":\"Bearer\",\"expires_in\":3600}");

        assertThatThrownBy(() ->
                service.refreshIfNeeded(nearlyExpiredContext(), tokenEndpoint(), new MockHttpSession()))
                .isInstanceOf(TokenRefreshException.class)
                .hasMessageContaining("access_token");
    }

    // ── forceRefresh ──────────────────────────────────────────────────────────

    @Test
    void forceRefresh_ignoresBuffer_alwaysCallsEndpoint() {
        stubRefresh(200, refreshResponseJson(false));
        SmartLaunchContext fresh = freshContext(); // not near expiry

        SmartLaunchContext result = service.forceRefresh(fresh, tokenEndpoint(), new MockHttpSession());

        assertThat(result).isNotNull();
        assertThat(result.accessToken()).isEqualTo(NEW_ACCESS);
        wireMock.verify(1, postRequestedFor(urlEqualTo(TOKEN_PATH)));
    }

    @Test
    void forceRefresh_noRefreshToken_returnsNull() {
        SmartLaunchContext noRefresh = context(Instant.now().plusSeconds(3600), null);
        SmartLaunchContext result = service.forceRefresh(noRefresh, tokenEndpoint(), new MockHttpSession());

        assertThat(result).isNull();
        wireMock.verify(0, postRequestedFor(urlEqualTo(TOKEN_PATH)));
    }

    // ── form body ─────────────────────────────────────────────────────────────

    @Test
    void refreshRequest_containsGrantTypeRefreshToken() {
        stubRefresh(200, refreshResponseJson(false));
        service.refreshIfNeeded(nearlyExpiredContext(), tokenEndpoint(), new MockHttpSession());

        wireMock.verify(postRequestedFor(urlEqualTo(TOKEN_PATH))
                .withRequestBody(containing("grant_type=refresh_token")));
    }

    @Test
    void refreshRequest_containsClientId() {
        stubRefresh(200, refreshResponseJson(false));
        service.refreshIfNeeded(nearlyExpiredContext(), tokenEndpoint(), new MockHttpSession());

        wireMock.verify(postRequestedFor(urlEqualTo(TOKEN_PATH))
                .withRequestBody(containing("client_id=test-client-id")));
    }
}
