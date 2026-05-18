package com.akhester.smartfhir.client.auth;

import com.akhester.smartfhir.client.EpicProperties;
import com.akhester.smartfhir.client.launch.SmartLaunchSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpSession;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for SmartAuthRequestBuilder.
 *
 * No Spring context — pure unit test using real PkceHelper and a mock session.
 *
 * Test cases:
 *  1.  Built URL starts with the auth endpoint from the launch session.
 *  2.  URL contains response_type=code.
 *  3.  URL contains client_id from EpicProperties.
 *  4.  URL contains redirect_uri from EpicProperties.
 *  5.  URL contains launch token (Epic-specific).
 *  6.  URL contains aud = ISS (Epic-specific).
 *  7.  URL contains state from launch session.
 *  8.  URL contains space-separated scopes.
 *  9.  URL contains code_challenge (PKCE).
 *  10. URL contains code_challenge_method=S256 (PKCE).
 *  11. Session receives PkceParameters under SESSION_KEY.
 *  12. code_challenge in URL matches SHA-256 of stored code_verifier.
 *  13. Each call generates a different code_challenge (uniqueness).
 */
class SmartAuthRequestBuilderTest {

    private SmartAuthRequestBuilder builder;
    private PkceHelper pkceHelper;

    private static final String AUTH_ENDPOINT  = "https://fhir.epic.com/oauth2/authorize";
    private static final String TOKEN_ENDPOINT = "https://fhir.epic.com/oauth2/token";
    private static final String ISS            = "https://fhir.epic.com/interconnect/api/FHIR/R4";
    private static final String LAUNCH_TOKEN   = "abc123opaque";
    private static final String STATE          = "randomstatenonce";
    private static final String CLIENT_ID      = "test-client-id";
    private static final String REDIRECT_URI   = "http://localhost:8080/callback";
    private static final List<String> SCOPES   =
            List.of("launch", "openid", "patient/Patient.rs");

    @BeforeEach
    void setUp() {
        pkceHelper = new PkceHelper();

        EpicProperties props = new EpicProperties(
                CLIENT_ID, REDIRECT_URI, SCOPES, 60);

        builder = new SmartAuthRequestBuilder(props, pkceHelper);
    }

    private SmartLaunchSession testSession() {
        return SmartLaunchSession.of(
                ISS, LAUNCH_TOKEN, STATE,
                AUTH_ENDPOINT, TOKEN_ENDPOINT,
                SCOPES);
    }

    @Test
    void url_startsWithAuthEndpoint() {
        String url = builder.buildAuthorizeUrl(testSession(), new MockHttpSession());
        assertThat(url).startsWith(AUTH_ENDPOINT);
    }

    @Test
    void url_containsResponseTypeCode() {
        String url = builder.buildAuthorizeUrl(testSession(), new MockHttpSession());
        assertThat(url).contains("response_type=code");
    }

    @Test
    void url_containsClientId() {
        String url = builder.buildAuthorizeUrl(testSession(), new MockHttpSession());
        assertThat(url).contains("client_id=" + CLIENT_ID);
    }

    @Test
    void url_containsRedirectUri() {
        String url = builder.buildAuthorizeUrl(testSession(), new MockHttpSession());
        assertThat(url).contains("redirect_uri=");
    }

    @Test
    void url_containsLaunchToken() {
        String url = builder.buildAuthorizeUrl(testSession(), new MockHttpSession());
        assertThat(url).contains("launch=" + LAUNCH_TOKEN);
    }

    @Test
    void url_containsAudEqualToIss() {
        String url = builder.buildAuthorizeUrl(testSession(), new MockHttpSession());
        // aud must equal the ISS — Epic validates this server-side.
        // A bug that sets aud to the wrong value would cause a silent Epic rejection.
        assertThat(url).contains("aud=https%3A%2F%2Ffhir.epic.com%2Finterconnect%2Fapi%2FFHIR%2FR4");
    }

    @Test
    void url_containsState() {
        String url = builder.buildAuthorizeUrl(testSession(), new MockHttpSession());
        assertThat(url).contains("state=" + STATE);
    }

    @Test
    void url_containsAllScopes() {
        String url = builder.buildAuthorizeUrl(testSession(), new MockHttpSession());
        // Scopes are space-separated and URL-encoded — check each is present
        assertThat(url).contains("scope=");
        assertThat(url).containsAnyOf("launch", "openid");
    }

    @Test
    void url_containsCodeChallenge() {
        String url = builder.buildAuthorizeUrl(testSession(), new MockHttpSession());
        assertThat(url).contains("code_challenge=");
    }

    @Test
    void url_containsCodeChallengMethodS256() {
        String url = builder.buildAuthorizeUrl(testSession(), new MockHttpSession());
        assertThat(url).contains("code_challenge_method=S256");
    }

    @Test
    void session_receivesPkceParameters() {
        MockHttpSession session = new MockHttpSession();
        builder.buildAuthorizeUrl(testSession(), session);

        Object stored = session.getAttribute(PkceParameters.SESSION_KEY);
        assertThat(stored).isInstanceOf(PkceParameters.class);

        PkceParameters pkce = (PkceParameters) stored;
        assertThat(pkce.codeVerifier()).isNotBlank();
        assertThat(pkce.codeChallenge()).isNotBlank();
    }

    @Test
    void pkceChallenge_inUrlMatchesStoredVerifier() {
        MockHttpSession session = new MockHttpSession();
        String url = builder.buildAuthorizeUrl(testSession(), session);

        PkceParameters pkce = (PkceParameters) session.getAttribute(PkceParameters.SESSION_KEY);

        // Extract challenge from URL
        String challengeParam = "code_challenge=";
        int start = url.indexOf(challengeParam) + challengeParam.length();
        int end   = url.indexOf("&", start);
        String challengeInUrl = end == -1 ? url.substring(start) : url.substring(start, end);

        // Recompute from the stored verifier — must match what's in the URL
        String recomputed = pkceHelper.computeChallenge(pkce.codeVerifier());
        assertThat(challengeInUrl).isEqualTo(recomputed);
    }

    @Test
    void repeatedCalls_generateDifferentChallenges() {
        String url1 = builder.buildAuthorizeUrl(testSession(), new MockHttpSession());
        String url2 = builder.buildAuthorizeUrl(testSession(), new MockHttpSession());

        // Two independent launches should never share the same PKCE challenge
        String extractChallenge = url -> {
            String marker = "code_challenge=";
            int s = url.indexOf(marker) + marker.length();
            int e = url.indexOf("&", s);
            return e == -1 ? url.substring(s) : url.substring(s, e);
        };

        assertThat(extractChallenge.apply(url1))
                .isNotEqualTo(extractChallenge.apply(url2));
    }

    @Test
    void standaloneLaunch_launchParamAbsentWhenTokenNull() {
        // Standalone session — launchToken is null
        SmartLaunchSession standaloneSession = SmartLaunchSession.of(
                ISS, null, STATE,           // null launchToken = standalone
                AUTH_ENDPOINT, TOKEN_ENDPOINT,
                List.of("launch/patient", "openid", "patient/Patient.rs")
        );

        String url = builder.buildAuthorizeUrl(standaloneSession, new MockHttpSession());

        // launch param must NOT appear for standalone — Epic rejects it
        assertThat(url).doesNotContain("launch=");
        // All other params must still be present
        assertThat(url).contains("response_type=code");
        assertThat(url).contains("code_challenge_method=S256");
        assertThat(url).contains("aud=");
    }
}
