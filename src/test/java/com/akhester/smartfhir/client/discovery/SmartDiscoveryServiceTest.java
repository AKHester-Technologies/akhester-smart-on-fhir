package com.akhester.smartfhir.client.discovery;

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
 * Unit tests for SmartDiscoveryService.
 *
 * WireMock runs on a random port — no fixed port conflicts, safe for parallel CI.
 *
 * Test cases:
 *  1. Happy path — valid discovery doc returned and parsed correctly.
 *  2. Caching — second call does NOT hit the network (WireMock verifies 1 request).
 *  3. Cache eviction — evict() forces a fresh fetch.
 *  4. Trailing slash on ISS — normalized before the URL is built.
 *  5. 404 from ISS — SmartDiscoveryException thrown.
 *  6. Malformed JSON — SmartDiscoveryException thrown.
 *  7. Missing authorization_endpoint — validate() rejects the document.
 *  8. Blank ISS — IllegalArgumentException thrown immediately.
 */
class SmartDiscoveryServiceTest {

    private WireMockServer wireMock;
    private SmartDiscoveryService service;

    private static final String DISCOVERY_PATH = "/.well-known/smart-configuration";

    /** Minimal valid Epic smart-configuration JSON. */
    private static final String VALID_CONFIG_JSON = """
            {
              "authorization_endpoint": "http://localhost:%d/oauth2/authorize",
              "token_endpoint":         "http://localhost:%d/oauth2/token",
              "capabilities": [
                "launch-ehr",
                "client-public",
                "context-ehr-patient",
                "permission-patient",
                "sso-openid-connect"
              ],
              "code_challenge_methods_supported": ["S256"],
              "response_types_supported": ["code"],
              "scopes_supported": ["launch", "openid", "patient/Patient.rs"]
            }
            """;

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
        service = new SmartDiscoveryService(props, new ObjectMapper());
    }

    @AfterEach
    void tearDown() {
        wireMock.stop();
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private String iss() {
        return "http://localhost:" + wireMock.port() + "/fhir/r4";
    }

    private void stubDiscovery(int status, String body) {
        wireMock.stubFor(get(urlEqualTo("/fhir/r4" + DISCOVERY_PATH))
                .willReturn(aResponse()
                        .withStatus(status)
                        .withHeader("Content-Type", "application/json")
                        .withBody(body)));
    }

    private String validJson() {
        return VALID_CONFIG_JSON.formatted(wireMock.port(), wireMock.port());
    }

    // ── test cases ────────────────────────────────────────────────────────────

    @Test
    void happyPath_parsesAllFields() {
        stubDiscovery(200, validJson());

        SmartConfiguration config = service.discover(iss());

        assertThat(config.authorizationEndpoint())
                .isEqualTo("http://localhost:%d/oauth2/authorize".formatted(wireMock.port()));
        assertThat(config.tokenEndpoint())
                .isEqualTo("http://localhost:%d/oauth2/token".formatted(wireMock.port()));
        assertThat(config.capabilities()).contains("launch-ehr", "sso-openid-connect");
        assertThat(config.supportsEhrLaunch()).isTrue();
        assertThat(config.supportsPkceS256()).isTrue();
    }

    @Test
    void caching_secondCallDoesNotHitNetwork() {
        stubDiscovery(200, validJson());

        service.discover(iss());
        service.discover(iss()); // should be served from cache

        // WireMock should have received exactly 1 request, not 2.
        wireMock.verify(1, getRequestedFor(urlEqualTo("/fhir/r4" + DISCOVERY_PATH)));
    }

    @Test
    void evict_forcesRefetch() {
        stubDiscovery(200, validJson());

        service.discover(iss());
        service.evict(iss());
        service.discover(iss()); // cache was cleared — must hit network again

        wireMock.verify(2, getRequestedFor(urlEqualTo("/fhir/r4" + DISCOVERY_PATH)));
    }

    @Test
    void trailingSlashOnIss_isNormalized() {
        stubDiscovery(200, validJson());

        // Both ISS variants should normalise to the same cache key and hit the
        // network exactly twice (evict forces a re-fetch between them).
        SmartConfiguration c1 = service.discover(iss());
        service.evict(iss());
        SmartConfiguration c2 = service.discover(iss() + "/");

        // Same endpoints returned — normalisation produced the same document.
        assertThat(c1.authorizationEndpoint()).isEqualTo(c2.authorizationEndpoint());

        // Two network calls: one for c1, one for c2 after eviction.
        // If normalisation is broken, iss()+"/" hits a different cache key
        // and the stub would get a third call (or zero for the variant without a stub).
        wireMock.verify(2, getRequestedFor(urlEqualTo("/fhir/r4" + DISCOVERY_PATH)));
    }

    @Test
    void http404_throwsSmartDiscoveryException() {
        stubDiscovery(404, "Not Found");

        assertThatThrownBy(() -> service.discover(iss()))
                .isInstanceOf(SmartDiscoveryException.class)
                .hasMessageContaining("404");
    }

    @Test
    void malformedJson_throwsSmartDiscoveryException() {
        stubDiscovery(200, "{ this is not valid json }");

        assertThatThrownBy(() -> service.discover(iss()))
                .isInstanceOf(SmartDiscoveryException.class)
                .hasMessageContaining("parse");
    }

    @Test
    void missingAuthorizationEndpoint_throwsOnValidation() {
        String noAuthEndpoint = """
                {
                  "token_endpoint": "http://localhost/token",
                  "capabilities": ["launch-ehr"]
                }
                """;
        stubDiscovery(200, noAuthEndpoint);

        assertThatThrownBy(() -> service.discover(iss()))
                .isInstanceOf(SmartDiscoveryException.class)
                .hasMessageContaining("authorization_endpoint");
    }

    @Test
    void blankIss_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> service.discover("  "))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> service.discover(null))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
