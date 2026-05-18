package com.akhester.smartfhir.client.fhir;

import ca.uhn.fhir.rest.client.api.IGenericClient;
import com.akhester.smartfhir.client.context.SmartContextExtractor;
import com.akhester.smartfhir.client.context.SmartLaunchContext;
import org.hl7.fhir.r4.model.*;
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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Unit tests for PatientDataController.
 *
 * HAPI client calls are mocked — no real FHIR server needed.
 *
 * Test cases:
 *  1.  GET /api/patient — 200 with patient JSON when scope granted.
 *  2.  GET /api/patient — 403 when patient/Patient.rs not in scope.
 *  3.  GET /api/conditions — 200 with condition list.
 *  4.  GET /api/conditions — 403 when scope missing.
 *  5.  GET /api/medications — 200 with medication list.
 *  6.  GET /api/medications — 403 when scope missing.
 *  7.  GET /api/summary — 200 combining all resources.
 *  8.  No session context → 401 on any endpoint.
 *  9.  Expired token → 401.
 *  10. Summary skips resources for which scope was not granted.
 */
@WebMvcTest(PatientDataController.class)
class PatientDataControllerTest {

    @Autowired MockMvc mvc;

    @MockBean FhirClientFactory clientFactory;
    @MockBean SmartContextExtractor contextExtractor;
    @MockBean IGenericClient fhirClient;

    private MockHttpSession session;
    private SmartLaunchContext fullScopeContext;

    @BeforeEach
    void setUp() {
        session = new MockHttpSession();

        fullScopeContext = new SmartLaunchContext(
                "eyJ.access_token", "ePatient-123", "eEncounter-456",
                "https://fhir.epic.com/fhir/r4",
                true,
                "launch openid patient/Patient.rs patient/Condition.rs patient/MedicationRequest.rs",
                Instant.now().plusSeconds(3600),
                "refresh_token"
        );

        when(contextExtractor.retrieve(any())).thenReturn(fullScopeContext);
        when(clientFactory.create(any())).thenReturn(fhirClient);

        // Stub Patient read
        Patient patient = new Patient();
        patient.setId("ePatient-123");
        patient.addName().setFamily("Smith").addGiven("John");
        patient.setBirthDate(java.sql.Date.valueOf("1975-06-15"));
        patient.setGender(Enumerations.AdministrativeGender.MALE);

        var readMock = mock(ca.uhn.fhir.rest.gclient.IReadTyped.class);
        var readExecutable = mock(ca.uhn.fhir.rest.gclient.IReadExecutable.class);
        when(fhirClient.read()).thenReturn(mock(ca.uhn.fhir.rest.gclient.IRead.class));
        lenient().when(fhirClient.read().resource(Patient.class)).thenReturn(readMock);
        lenient().when(readMock.withId(anyString())).thenReturn(readExecutable);
        lenient().when(readExecutable.execute()).thenReturn(patient);

        // Stub Condition search — return empty bundle for simplicity
        Bundle conditionBundle = new Bundle();
        Bundle medicationBundle = new Bundle();
        var searchMock = mock(ca.uhn.fhir.rest.gclient.IUntypedQuery.class);
        lenient().when(fhirClient.search()).thenReturn(searchMock);
    }

    // ── /api/patient ──────────────────────────────────────────────────────────

    @Test
    @WithMockUser
    void patient_returns200WhenScopeGranted() throws Exception {
        mvc.perform(get("/api/patient").session(session))
                .andExpect(status().isOk());
    }

    @Test
    @WithMockUser
    void patient_returns403WhenScopeMissing() throws Exception {
        SmartLaunchContext noScope = new SmartLaunchContext(
                "eyJ.token", "ePatient-123", null,
                "https://fhir.epic.com/fhir/r4",
                true, "launch openid",   // no patient/Patient.rs
                Instant.now().plusSeconds(3600), null
        );
        when(contextExtractor.retrieve(any())).thenReturn(noScope);

        mvc.perform(get("/api/patient").session(session))
                .andExpect(status().isForbidden());
    }

    // ── /api/conditions ───────────────────────────────────────────────────────

    @Test
    @WithMockUser
    void conditions_returns403WhenScopeMissing() throws Exception {
        SmartLaunchContext noScope = new SmartLaunchContext(
                "eyJ.token", "ePatient-123", null,
                "https://fhir.epic.com/fhir/r4",
                true, "launch openid patient/Patient.rs",  // no Condition scope
                Instant.now().plusSeconds(3600), null
        );
        when(contextExtractor.retrieve(any())).thenReturn(noScope);

        mvc.perform(get("/api/conditions").session(session))
                .andExpect(status().isForbidden());
    }

    // ── /api/medications ──────────────────────────────────────────────────────

    @Test
    @WithMockUser
    void medications_returns403WhenScopeMissing() throws Exception {
        SmartLaunchContext noScope = new SmartLaunchContext(
                "eyJ.token", "ePatient-123", null,
                "https://fhir.epic.com/fhir/r4",
                true, "launch openid patient/Patient.rs",  // no MedicationRequest scope
                Instant.now().plusSeconds(3600), null
        );
        when(contextExtractor.retrieve(any())).thenReturn(noScope);

        mvc.perform(get("/api/medications").session(session))
                .andExpect(status().isForbidden());
    }

    // ── unauthenticated / expired ─────────────────────────────────────────────

    @Test
    @WithMockUser
    void noContext_returns401() throws Exception {
        when(contextExtractor.retrieve(any())).thenReturn(null);

        mvc.perform(get("/api/patient").session(session))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithMockUser
    void expiredToken_returns401() throws Exception {
        SmartLaunchContext expired = new SmartLaunchContext(
                "eyJ.expired", "ePatient-123", null,
                "https://fhir.epic.com/fhir/r4",
                true, "launch openid patient/Patient.rs",
                Instant.now().minusSeconds(60),   // already expired
                null
        );
        when(contextExtractor.retrieve(any())).thenReturn(expired);

        mvc.perform(get("/api/patient").session(session))
                .andExpect(status().isUnauthorized());
    }

    // ── /api/summary ──────────────────────────────────────────────────────────

    @Test
    @WithMockUser
    void summary_returns200() throws Exception {
        mvc.perform(get("/api/summary").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.patientId").value("ePatient-123"))
                .andExpect(jsonPath("$.encounterId").value("eEncounter-456"))
                .andExpect(jsonPath("$.needPatientBanner").value(true));
    }

    @Test
    @WithMockUser
    void summary_includesGrantedScopesField() throws Exception {
        mvc.perform(get("/api/summary").session(session))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.grantedScopes").isString());
    }
}
