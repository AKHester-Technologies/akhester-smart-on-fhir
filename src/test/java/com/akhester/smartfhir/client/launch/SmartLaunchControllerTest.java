package com.akhester.smartfhir.client.launch;

import com.akhester.smartfhir.client.EpicProperties;
import com.akhester.smartfhir.client.auth.SmartAuthRequestBuilder;
import com.akhester.smartfhir.client.discovery.SmartConfiguration;
import com.akhester.smartfhir.client.discovery.SmartDiscoveryException;
import com.akhester.smartfhir.client.discovery.SmartDiscoveryService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for SmartLaunchController.
 *
 * Uses @WebMvcTest — only the web layer is loaded, SmartDiscoveryService is mocked.
 * This means tests run in milliseconds with no network calls.
 *
 * Test cases:
 *  1.  Happy path — 302 redirect to authorize URL with all required params.
 *  2.  Session contains SmartLaunchSession after successful launch.
 *  3.  State nonce is present in both the redirect URL and the session.
 *  4.  Missing iss → 400.
 *  5.  Missing launch → 400.
 *  6.  HTTP (non-HTTPS, non-localhost) iss → 400.
 *  7.  Discovery failure → 502.
 *  8.  Authorize URL contains: client_id, redirect_uri, launch, scope, aud, state.
 *  9.  Localhost iss is allowed (for sandbox/dev).
 *  10. HTTPS iss is accepted.
 */
@WebMvcTest(SmartLaunchController.class)
class SmartLaunchControllerTest {

    @Autowired
    MockMvc mvc;

    @MockBean
    SmartDiscoveryService discoveryService;

    @MockBean
    EpicProperties epicProperties;

    @MockBean
    SmartAuthRequestBuilder authRequestBuilder;

    private static final String ISS = "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4";
    private static final String LAUNCH_TOKEN = "abc123opaque";
    private static final String AUTH_ENDPOINT = "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/authorize";
    private static final String TOKEN_ENDPOINT = "https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token";

    @BeforeEach
    void setUp() {
        // Wire EpicProperties mock
        when(epicProperties.clientId()).thenReturn("test-client-id");
        when(epicProperties.redirectUri()).thenReturn("http://localhost:8080/callback");
        when(epicProperties.scopes()).thenReturn(
                List.of("launch", "openid", "patient/Patient.rs"));
        when(epicProperties.discoveryCacheMinutes()).thenReturn(60);

        // Wire SmartAuthRequestBuilder mock — returns a fake authorize URL
        when(authRequestBuilder.buildAuthorizeUrl(any(), any()))
                .thenReturn(AUTH_ENDPOINT + "?response_type=code&client_id=test-client-id"
                        + "&state=teststate&launch=" + LAUNCH_TOKEN
                        + "&aud=" + ISS
                        + "&code_challenge=testchallenge&code_challenge_method=S256");

        // Wire SmartDiscoveryService mock — returns a valid config by default
        SmartConfiguration config = new SmartConfiguration(
                AUTH_ENDPOINT, TOKEN_ENDPOINT,
                List.of("client_secret_basic"),
                List.of("launch", "openid"),
                List.of("code"),
                List.of("launch-ehr", "sso-openid-connect"),
                List.of("S256")
        );
        when(discoveryService.discover(anyString())).thenReturn(config);
    }

    @Test
    @WithMockUser
    void happyPath_returns302ToAuthorizeEndpoint() throws Exception {
        mvc.perform(get("/launch")
                        .param("iss", ISS)
                        .param("launch", LAUNCH_TOKEN))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern(AUTH_ENDPOINT + "**"));
    }

    @Test
    @WithMockUser
    void happyPath_sessionContainsLaunchSession() throws Exception {
        MockHttpSession session = new MockHttpSession();

        mvc.perform(get("/launch")
                        .param("iss", ISS)
                        .param("launch", LAUNCH_TOKEN)
                        .session(session))
                .andExpect(status().is3xxRedirection());

        Object attr = session.getAttribute(SmartLaunchSession.SESSION_KEY);
        assertThat(attr).isInstanceOf(SmartLaunchSession.class);

        SmartLaunchSession launchSession = (SmartLaunchSession) attr;
        assertThat(launchSession.iss()).isEqualTo(ISS);
        assertThat(launchSession.launchToken()).isEqualTo(LAUNCH_TOKEN);
        assertThat(launchSession.authEndpoint()).isEqualTo(AUTH_ENDPOINT);
        assertThat(launchSession.tokenEndpoint()).isEqualTo(TOKEN_ENDPOINT);
        assertThat(launchSession.state()).isNotBlank();
        assertThat(launchSession.initiatedAt()).isNotNull();
    }

    @Test
    @WithMockUser
    void stateNonce_isPresentInRedirectUrlAndSession() throws Exception {
        MockHttpSession session = new MockHttpSession();

        MvcResult result = mvc.perform(get("/launch")
                        .param("iss", ISS)
                        .param("launch", LAUNCH_TOKEN)
                        .session(session))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        SmartLaunchSession launchSession =
                (SmartLaunchSession) session.getAttribute(SmartLaunchSession.SESSION_KEY);

        String redirectUrl = result.getResponse().getRedirectedUrl();
        assertThat(redirectUrl).contains("state=" + launchSession.state());
    }

    @Test
    @WithMockUser
    void authorizeUrl_containsAllRequiredEpicParams() throws Exception {
        MvcResult result = mvc.perform(get("/launch")
                        .param("iss", ISS)
                        .param("launch", LAUNCH_TOKEN))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String url = result.getResponse().getRedirectedUrl();
        assertThat(url)
                .contains("response_type=code")
                .contains("client_id=test-client-id")
                .contains("redirect_uri=")
                .contains("launch=" + LAUNCH_TOKEN)
                .contains("scope=")
                .contains("state=")
                .contains("aud=");  // Epic-specific — must equal the ISS
    }

    @Test
    @WithMockUser
    void missingIss_returns400() throws Exception {
        mvc.perform(get("/launch")
                        .param("launch", LAUNCH_TOKEN))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser
    void missingLaunch_returns400() throws Exception {
        mvc.perform(get("/launch")
                        .param("iss", ISS))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser
    void httpIss_notLocalhost_returns400() throws Exception {
        mvc.perform(get("/launch")
                        .param("iss", "http://some-hospital.com/fhir/r4")
                        .param("launch", LAUNCH_TOKEN))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser
    void localhostIss_isAllowed() throws Exception {
        mvc.perform(get("/launch")
                        .param("iss", "http://localhost:8080/fhir/r4")
                        .param("launch", LAUNCH_TOKEN))
                .andExpect(status().is3xxRedirection());
    }

    @Test
    @WithMockUser
    void httpsIss_isAccepted() throws Exception {
        mvc.perform(get("/launch")
                        .param("iss", ISS)
                        .param("launch", LAUNCH_TOKEN))
                .andExpect(status().is3xxRedirection());

        verify(discoveryService, times(1)).discover(ISS);
    }

    @Test
    @WithMockUser
    void discoveryFailure_returns502() throws Exception {
        when(discoveryService.discover(anyString()))
                .thenThrow(new SmartDiscoveryException("Connection refused"));

        mvc.perform(get("/launch")
                        .param("iss", ISS)
                        .param("launch", LAUNCH_TOKEN))
                .andExpect(status().isBadGateway());
    }

    // ── standalone launch (no launch param) ──────────────────────────────────

    @Test
    @WithMockUser
    void standaloneLaunch_missingLaunchParam_returns302() throws Exception {
        // Standalone launch: iss present, launch absent — should still redirect
        mvc.perform(get("/launch")
                        .param("iss", ISS))          // no launch param
                .andExpect(status().is3xxRedirection());
    }

    @Test
    @WithMockUser
    void standaloneLaunch_sessionLaunchTokenIsNull() throws Exception {
        MockHttpSession session = new MockHttpSession();

        mvc.perform(get("/launch")
                        .param("iss", ISS)
                        .session(session))
                .andExpect(status().is3xxRedirection());

        SmartLaunchSession launchSession =
                (SmartLaunchSession) session.getAttribute(SmartLaunchSession.SESSION_KEY);
        assertThat(launchSession).isNotNull();
        assertThat(launchSession.launchToken()).isNull();
    }

    @Test
    @WithMockUser
    void standaloneLaunch_scopesContainLaunchPatient() throws Exception {
        MockHttpSession session = new MockHttpSession();

        mvc.perform(get("/launch")
                        .param("iss", ISS)
                        .session(session))
                .andExpect(status().is3xxRedirection());

        SmartLaunchSession launchSession =
                (SmartLaunchSession) session.getAttribute(SmartLaunchSession.SESSION_KEY);
        // Standalone scopes should include launch/patient but not bare launch
        assertThat(launchSession.scopes()).contains("launch/patient");
        assertThat(launchSession.scopes()).doesNotContain("launch");
    }
}
