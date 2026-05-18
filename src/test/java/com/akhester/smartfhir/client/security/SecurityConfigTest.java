package com.akhester.smartfhir.client.security;

import com.akhester.smartfhir.client.context.SmartContextExtractor;
import com.akhester.smartfhir.client.context.SmartLaunchContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for SecurityConfig — verifies the actual filter chain
 * behaviour with the full Spring Boot context loaded.
 *
 * Uses @SpringBootTest (not @WebMvcTest) because SecurityConfig wires
 * beans from multiple packages. @WebMvcTest only loads the web layer,
 * which misses the SmartSecurityFilter registration.
 *
 * Test cases:
 *  1.  GET /launch — 200/302 without authentication (Epic calls this unauthenticated).
 *  2.  GET /callback — accessible without authentication.
 *  3.  GET /health — 200 without authentication.
 *  4.  GET /actuator/health — 200 without authentication.
 *  5.  GET /api/patient — 401 without SMART session.
 *  6.  GET /api/patient — not 401 with valid SMART session.
 *  7.  GET /api/conditions — 401 without SMART session.
 *  8.  GET /api/medications — 401 without SMART session.
 *  9.  GET / — 401 without SMART session.
 *  10. Unknown route — 403 (denyAll).
 */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigTest {

    @Autowired MockMvc mvc;

    @MockBean SmartContextExtractor contextExtractor;

    private SmartLaunchContext validContext() {
        return new SmartLaunchContext(
                "eyJ.token", "ePatient-123", null,
                "https://fhir.epic.com/fhir/r4",
                true,
                "launch openid patient/Patient.rs patient/Condition.rs patient/MedicationRequest.rs",
                Instant.now().plusSeconds(3600), null
        );
    }

    private MockHttpSession authenticatedSession() {
        MockHttpSession session = new MockHttpSession();
        when(contextExtractor.retrieve(any())).thenReturn(validContext());
        return session;
    }

    // ── public routes ─────────────────────────────────────────────────────────

    @Test
    void launch_isPubliclyAccessible() throws Exception {
        // Epic calls /launch with no prior session — must not be blocked.
        // Returns 400 (missing iss/launch params) not 401 — params are missing
        // but the route itself is accessible unauthenticated.
        mvc.perform(get("/launch"))
                .andExpect(result ->
                        assertThat(result.getResponse().getStatus()).isNotEqualTo(401));
    }

    @Test
    void callback_isPubliclyAccessible() throws Exception {
        // Epic redirects to /callback — must be reachable before session exists.
        mvc.perform(get("/callback"))
                .andExpect(result ->
                        assertThat(result.getResponse().getStatus()).isNotEqualTo(401));
    }

    @Test
    void health_returns200WithoutAuthentication() throws Exception {
        mvc.perform(get("/health"))
                .andExpect(status().isOk());
    }

    @Test
    void actuatorHealth_isPubliclyAccessible() throws Exception {
        mvc.perform(get("/actuator/health"))
                .andExpect(status().isOk());
    }

    // ── protected routes — unauthenticated ───────────────────────────────────

    @Test
    void apiPatient_returns401WithoutSmartSession() throws Exception {
        when(contextExtractor.retrieve(any())).thenReturn(null);
        mvc.perform(get("/api/patient"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void apiConditions_returns401WithoutSmartSession() throws Exception {
        when(contextExtractor.retrieve(any())).thenReturn(null);
        mvc.perform(get("/api/conditions"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void apiMedications_returns401WithoutSmartSession() throws Exception {
        when(contextExtractor.retrieve(any())).thenReturn(null);
        mvc.perform(get("/api/medications"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void appHome_returns401WithoutSmartSession() throws Exception {
        when(contextExtractor.retrieve(any())).thenReturn(null);
        mvc.perform(get("/"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void unknownRoute_returns403_denyAll() throws Exception {
        // anyRequest().denyAll() — unknown routes return 403 not 404.
        // This prevents route enumeration — attackers can't distinguish
        // "doesn't exist" from "you're not allowed".
        when(contextExtractor.retrieve(any())).thenReturn(null);
        mvc.perform(get("/some/unknown/path"))
                .andExpect(status().isForbidden());
    }

    // ── protected routes — authenticated ─────────────────────────────────────

    @Test
    void apiPatient_notBlockedBySecurityWithValidSession() throws Exception {
        // With a valid SMART session the security layer permits the request.
        // The response may still be 403 (missing scope) or 200 — but NOT 401.
        // This confirms SecurityConfig allows authenticated requests through.
        MockHttpSession session = authenticatedSession();
        mvc.perform(get("/api/patient").session(session))
                .andExpect(result ->
                        assertThat(result.getResponse().getStatus()).isNotEqualTo(401));
    }

    @Test
    void expiredToken_returns401() throws Exception {
        // An expired token in the session must NOT grant access.
        SmartLaunchContext expired = new SmartLaunchContext(
                "eyJ.old_token", "ePatient-123", null,
                "https://fhir.epic.com/fhir/r4",
                true, "launch openid",
                Instant.now().minusSeconds(60), null
        );
        when(contextExtractor.retrieve(any())).thenReturn(expired);
        MockHttpSession session = new MockHttpSession();

        mvc.perform(get("/api/patient").session(session))
                .andExpect(status().isUnauthorized());
    }
}
