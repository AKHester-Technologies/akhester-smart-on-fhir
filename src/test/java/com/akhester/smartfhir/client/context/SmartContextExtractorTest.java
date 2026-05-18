package com.akhester.smartfhir.client.context;

import com.akhester.smartfhir.client.oidc.IdTokenValidator;
import com.akhester.smartfhir.client.token.SmartCallbackController;
import com.akhester.smartfhir.client.token.SmartTokenResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpSession;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for SmartContextExtractor.
 *
 * Pure unit test — no Spring context, just a MockHttpSession.
 * IdTokenValidator is mocked — its own tests are in IdTokenValidatorTest.
 */
@ExtendWith(MockitoExtension.class)
class SmartContextExtractorTest {

    @Mock IdTokenValidator idTokenValidator;

    private SmartContextExtractor extractor;
    private MockHttpSession session;

    private static final String ISS          = "https://fhir.epic.com/fhir/r4";
    private static final String ACCESS_TOKEN = "eyJ.access_token_abc";
    private static final String PATIENT_ID   = "ePatient-ABC123";
    private static final String ENCOUNTER_ID = "eEncounter-XYZ789";
    private static final Instant EXPIRES_AT  = Instant.now().plusSeconds(3600);

    @BeforeEach
    void setUp() {
        extractor = new SmartContextExtractor(idTokenValidator);
        session   = new MockHttpSession();
    }

    private SmartTokenResponse tokenResponse(String patient, String encounter) {
        return new SmartTokenResponse(
                ACCESS_TOKEN, "Bearer", 3600,
                "refresh_token_xyz",
                "launch openid patient/Patient.rs",
                "id_token_xyz",
                patient, encounter,
                true, null,
                EXPIRES_AT
        );
    }

    // ── extract ───────────────────────────────────────────────────────────────

    @Test
    void extract_storesContextInSessionUnderCorrectKey() {
        extractor.extract(tokenResponse(PATIENT_ID, ENCOUNTER_ID), ISS, session);

        assertThat(session.getAttribute(SmartLaunchContext.SESSION_KEY))
                .isInstanceOf(SmartLaunchContext.class);
    }

    @Test
    void extract_removesRawTokenResponseFromSession() {
        // Pre-populate what Task 5 would have stored
        session.setAttribute(SmartCallbackController.TOKEN_SESSION_KEY,
                tokenResponse(PATIENT_ID, ENCOUNTER_ID));

        extractor.extract(tokenResponse(PATIENT_ID, ENCOUNTER_ID), ISS, session);

        assertThat(session.getAttribute(SmartCallbackController.TOKEN_SESSION_KEY))
                .isNull();
    }

    @Test
    void extract_mapsPatientId() {
        SmartLaunchContext ctx =
                extractor.extract(tokenResponse(PATIENT_ID, ENCOUNTER_ID), ISS, session);
        assertThat(ctx.patientId()).isEqualTo(PATIENT_ID);
    }

    @Test
    void extract_mapsEncounterId() {
        SmartLaunchContext ctx =
                extractor.extract(tokenResponse(PATIENT_ID, ENCOUNTER_ID), ISS, session);
        assertThat(ctx.encounterId()).isEqualTo(ENCOUNTER_ID);
    }

    @Test
    void extract_setsFhirBaseUrlToIss() {
        SmartLaunchContext ctx =
                extractor.extract(tokenResponse(PATIENT_ID, ENCOUNTER_ID), ISS, session);
        assertThat(ctx.fhirBaseUrl()).isEqualTo(ISS);
    }

    @Test
    void extract_mapsNeedPatientBanner() {
        SmartLaunchContext ctx =
                extractor.extract(tokenResponse(PATIENT_ID, ENCOUNTER_ID), ISS, session);
        assertThat(ctx.needPatientBanner()).isTrue();
    }

    @Test
    void extract_mapsScope() {
        SmartLaunchContext ctx =
                extractor.extract(tokenResponse(PATIENT_ID, ENCOUNTER_ID), ISS, session);
        assertThat(ctx.scope()).isEqualTo("launch openid patient/Patient.rs");
    }

    @Test
    void extract_mapsExpiresAt() {
        SmartLaunchContext ctx =
                extractor.extract(tokenResponse(PATIENT_ID, ENCOUNTER_ID), ISS, session);
        assertThat(ctx.expiresAt()).isEqualTo(EXPIRES_AT);
    }

    @Test
    void extract_mapsAccessToken() {
        SmartLaunchContext ctx =
                extractor.extract(tokenResponse(PATIENT_ID, ENCOUNTER_ID), ISS, session);
        assertThat(ctx.accessToken()).isEqualTo(ACCESS_TOKEN);
    }

    @Test
    void extract_withNullEncounter_hasEncounterIsFalse() {
        SmartLaunchContext ctx =
                extractor.extract(tokenResponse(PATIENT_ID, null), ISS, session);
        assertThat(ctx.hasEncounter()).isFalse();
        assertThat(ctx.encounterId()).isNull();
    }

    // ── retrieve ──────────────────────────────────────────────────────────────

    @Test
    void retrieve_returnsContextWhenPresent() {
        extractor.extract(tokenResponse(PATIENT_ID, ENCOUNTER_ID), ISS, session);
        SmartLaunchContext retrieved = extractor.retrieve(session);

        assertThat(retrieved).isNotNull();
        assertThat(retrieved.patientId()).isEqualTo(PATIENT_ID);
    }

    @Test
    void retrieve_returnsNullWhenNotAuthenticated() {
        // Empty session — no launch has been completed
        assertThat(extractor.retrieve(session)).isNull();
    }

    // ── refresh ───────────────────────────────────────────────────────────────

    @Test
    void refresh_updatesAccessTokenAndExpiry() {
        SmartLaunchContext original =
                extractor.extract(tokenResponse(PATIENT_ID, ENCOUNTER_ID), ISS, session);

        String newToken   = "eyJ.new_access_token";
        Instant newExpiry = Instant.now().plusSeconds(7200);

        SmartLaunchContext refreshed = extractor.refresh(original, newToken, newExpiry, session);

        assertThat(refreshed.accessToken()).isEqualTo(newToken);
        assertThat(refreshed.expiresAt()).isEqualTo(newExpiry);
    }

    @Test
    void refresh_preservesPatientAndEncounter() {
        SmartLaunchContext original =
                extractor.extract(tokenResponse(PATIENT_ID, ENCOUNTER_ID), ISS, session);

        SmartLaunchContext refreshed = extractor.refresh(
                original, "new-token", Instant.now().plusSeconds(7200), session);

        assertThat(refreshed.patientId()).isEqualTo(PATIENT_ID);
        assertThat(refreshed.encounterId()).isEqualTo(ENCOUNTER_ID);
        assertThat(refreshed.fhirBaseUrl()).isEqualTo(ISS);
    }

    @Test
    void refresh_storesUpdatedContextInSession() {
        SmartLaunchContext original =
                extractor.extract(tokenResponse(PATIENT_ID, ENCOUNTER_ID), ISS, session);

        String newToken = "eyJ.refreshed";
        extractor.refresh(original, newToken, Instant.now().plusSeconds(7200), session);

        SmartLaunchContext inSession =
                (SmartLaunchContext) session.getAttribute(SmartLaunchContext.SESSION_KEY);
        assertThat(inSession.accessToken()).isEqualTo(newToken);
    }
}
