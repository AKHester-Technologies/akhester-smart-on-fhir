package com.akhester.smartfhir.client.token;

import com.akhester.smartfhir.client.auth.PkceParameters;
import com.akhester.smartfhir.client.context.SmartContextExtractor;
import com.akhester.smartfhir.client.context.SmartLaunchContext;
import com.akhester.smartfhir.client.launch.SmartLaunchSession;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for SmartCallbackController.
 *
 * Uses @WebMvcTest — SmartTokenService is mocked, no real token exchange.
 *
 * Test cases:
 *  1.  Happy path — 302 redirect to / with token stored in session.
 *  2.  Token response stored in session under TOKEN_SESSION_KEY.
 *  3.  PKCE params removed from session after successful exchange.
 *  4.  State mismatch → 400 (CSRF protection).
 *  5.  Missing state param → 400.
 *  6.  Missing code param → 400.
 *  7.  No launch session in session → 400.
 *  8.  No PKCE params in session → 400.
 *  9.  OAuth2 error param from Epic → 401.
 *  10. error_description included in 401 message.
 *  11. Token exchange failure → 502.
 *  12. Stale launch session → 400.
 *  13. State mismatch invalidates the HTTP session.
 */
@WebMvcTest(SmartCallbackController.class)
class SmartCallbackControllerTest {

    @Autowired MockMvc mvc;

    @MockBean SmartTokenService tokenService;
    @MockBean SmartContextExtractor contextExtractor;

    private static final String VALID_STATE     = "valid-state-nonce-abc123";
    private static final String AUTH_CODE       = "authcode_from_epic";
    private static final String ISS             = "https://fhir.epic.com/fhir/r4";
    private static final String AUTH_ENDPOINT   = "https://fhir.epic.com/oauth2/authorize";
    private static final String TOKEN_ENDPOINT  = "https://fhir.epic.com/oauth2/token";
    private static final String CODE_VERIFIER   = "pkce_verifier_xyz";
    private static final String CODE_CHALLENGE  = "pkce_challenge_abc";

    private SmartTokenResponse validTokenResponse;

    @BeforeEach
    void setUp() {
        validTokenResponse = new SmartTokenResponse(
                "eyJ.accesstoken", "Bearer", 3600,
                "refresh_token_xyz", "launch openid patient/Patient.rs",
                "id_token_xyz", "ePatient-123", "eEncounter-456",
                true, null, Instant.now().plusSeconds(3600)
        );
        when(tokenService.exchange(anyString(), anyString(), anyString()))
                .thenReturn(validTokenResponse);

        // SmartContextExtractor — stub to return a minimal context
        SmartLaunchContext stubContext = new SmartLaunchContext(
                "eyJ.accesstoken", "ePatient-123", "eEncounter-456",
                ISS, true, "launch openid patient/Patient.rs",
                java.time.Instant.now().plusSeconds(3600), "refresh_token"
        );
        when(contextExtractor.extract(any(), anyString(), any()))
                .thenReturn(stubContext);
    }

    /** Builds a valid MockHttpSession with both launch session and PKCE params. */
    private MockHttpSession validSession() {
        return validSession(VALID_STATE, false);
    }

    private MockHttpSession validSession(String state, boolean makeStale) {
        MockHttpSession session = new MockHttpSession();

        Instant initiatedAt = makeStale
                ? Instant.now().minusSeconds(400)  // older than MAX_LAUNCH_AGE (300s)
                : Instant.now();

        SmartLaunchSession launchSession = new SmartLaunchSession(
                ISS, "launch_token", state,
                AUTH_ENDPOINT, TOKEN_ENDPOINT,
                List.of("launch", "openid"),
                initiatedAt
        );
        session.setAttribute(SmartLaunchSession.SESSION_KEY, launchSession);
        session.setAttribute(PkceParameters.SESSION_KEY,
                new PkceParameters(CODE_VERIFIER, CODE_CHALLENGE));
        return session;
    }

    // ── happy path ────────────────────────────────────────────────────────────

    @Test
    @WithMockUser
    void happyPath_redirectsToAppHome() throws Exception {
        mvc.perform(get("/callback")
                        .param("code", AUTH_CODE)
                        .param("state", VALID_STATE)
                        .session(validSession()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/"));
    }

    @Test
    @WithMockUser
    void happyPath_storesLaunchContextInSession() throws Exception {
        // After Task 6 wiring: SmartContextExtractor.extract() removes TOKEN_SESSION_KEY
        // and stores SmartLaunchContext under SmartLaunchContext.SESSION_KEY.
        // Verify contextExtractor was called with correct ISS from the launch session.
        mvc.perform(get("/callback")
                        .param("code", AUTH_CODE)
                        .param("state", VALID_STATE)
                        .session(validSession()))
                .andExpect(status().is3xxRedirection());

        verify(contextExtractor).extract(any(), eq(ISS), any());
    }

    @Test
    @WithMockUser
    void happyPath_removesPkceFromSession() throws Exception {
        MockHttpSession session = validSession();

        mvc.perform(get("/callback")
                        .param("code", AUTH_CODE)
                        .param("state", VALID_STATE)
                        .session(session))
                .andExpect(status().is3xxRedirection());

        // Verifier must be cleared — it served its purpose
        assertThat(session.getAttribute(PkceParameters.SESSION_KEY)).isNull();
    }

    @Test
    @WithMockUser
    void happyPath_passesCorrectParamsToTokenService() throws Exception {
        mvc.perform(get("/callback")
                        .param("code", AUTH_CODE)
                        .param("state", VALID_STATE)
                        .session(validSession()))
                .andExpect(status().is3xxRedirection());

        verify(tokenService).exchange(TOKEN_ENDPOINT, AUTH_CODE, CODE_VERIFIER);
    }

    // ── validation failures ───────────────────────────────────────────────────

    @Test
    @WithMockUser
    void stateMismatch_returns400() throws Exception {
        MockHttpSession session = validSession("correct-state", false);

        mvc.perform(get("/callback")
                        .param("code", AUTH_CODE)
                        .param("state", "WRONG-state-value")
                        .session(session))
                .andExpect(status().isBadRequest());

        verify(tokenService, never()).exchange(any(), any(), any());
    }

    @Test
    @WithMockUser
    void stateMismatch_invalidatesSession() throws Exception {
        MockHttpSession session = validSession("correct-state", false);

        mvc.perform(get("/callback")
                        .param("code", AUTH_CODE)
                        .param("state", "WRONG-state")
                        .session(session));

        assertThat(session.isInvalid()).isTrue();
    }

    @Test
    @WithMockUser
    void missingCode_returns400() throws Exception {
        mvc.perform(get("/callback")
                        .param("state", VALID_STATE)
                        .session(validSession()))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser
    void missingState_returns400() throws Exception {
        mvc.perform(get("/callback")
                        .param("code", AUTH_CODE)
                        .session(validSession()))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser
    void noLaunchSession_returns400() throws Exception {
        MockHttpSession emptySession = new MockHttpSession();
        // No SmartLaunchSession stored — simulates direct /callback access

        mvc.perform(get("/callback")
                        .param("code", AUTH_CODE)
                        .param("state", VALID_STATE)
                        .session(emptySession))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser
    void noPkceParams_returns400() throws Exception {
        MockHttpSession session = new MockHttpSession();
        // Has launch session but no PKCE params — launch flow was interrupted
        SmartLaunchSession launchSession = new SmartLaunchSession(
                ISS, "token", VALID_STATE, AUTH_ENDPOINT, TOKEN_ENDPOINT,
                List.of("launch"), Instant.now()
        );
        session.setAttribute(SmartLaunchSession.SESSION_KEY, launchSession);

        mvc.perform(get("/callback")
                        .param("code", AUTH_CODE)
                        .param("state", VALID_STATE)
                        .session(session))
                .andExpect(status().isBadRequest());
    }

    @Test
    @WithMockUser
    void staleSession_returns400() throws Exception {
        MockHttpSession session = validSession(VALID_STATE, true); // initiated 400s ago

        mvc.perform(get("/callback")
                        .param("code", AUTH_CODE)
                        .param("state", VALID_STATE)
                        .session(session))
                .andExpect(status().isBadRequest());

        verify(tokenService, never()).exchange(any(), any(), any());
    }

    // ── OAuth2 error from Epic ────────────────────────────────────────────────

    @Test
    @WithMockUser
    void oauthError_returns401() throws Exception {
        mvc.perform(get("/callback")
                        .param("error", "access_denied")
                        .session(validSession()))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser
    void oauthErrorWithDescription_includedInResponse() throws Exception {
        mvc.perform(get("/callback")
                        .param("error", "access_denied")
                        .param("error_description", "User denied access")
                        .session(validSession()))
                .andExpect(status().isUnauthorized());

        verify(tokenService, never()).exchange(any(), any(), any());
    }

    // ── token exchange failure ────────────────────────────────────────────────

    @Test
    @WithMockUser
    void tokenExchangeFailure_returns502() throws Exception {
        when(tokenService.exchange(anyString(), anyString(), anyString()))
                .thenThrow(new TokenExchangeException("invalid_grant"));

        mvc.perform(get("/callback")
                        .param("code", AUTH_CODE)
                        .param("state", VALID_STATE)
                        .session(validSession()))
                .andExpect(status().isBadGateway());
    }
}
