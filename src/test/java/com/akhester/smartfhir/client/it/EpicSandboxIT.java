package com.akhester.smartfhir.client.it;

import ca.uhn.fhir.rest.client.api.IGenericClient;
import com.akhester.smartfhir.client.auth.PkceHelper;
import com.akhester.smartfhir.client.auth.PkceParameters;
import com.akhester.smartfhir.client.auth.SmartAuthRequestBuilder;
import com.akhester.smartfhir.client.context.SmartLaunchContext;
import com.akhester.smartfhir.client.discovery.SmartConfiguration;
import com.akhester.smartfhir.client.discovery.SmartDiscoveryService;
import com.akhester.smartfhir.client.fhir.FhirClientFactory;
import com.akhester.smartfhir.client.launch.SmartLaunchSession;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Condition;
import org.hl7.fhir.r4.model.Patient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests against Epic's non-production FHIR sandbox.
 *
 * <h3>Prerequisites</h3>
 * <ol>
 *   <li>Register at {@code https://fhir.epic.com} (free).</li>
 *   <li>Create an app → set redirect URI to {@code http://localhost:8080/callback}.</li>
 *   <li>Export: {@code export EPIC_CLIENT_ID=<your-non-production-client-id>}</li>
 * </ol>
 *
 * <h3>What this tests</h3>
 * <ul>
 *   <li><b>Discovery</b> — real {@code /.well-known/smart-configuration} from Epic.</li>
 *   <li><b>PKCE</b> — verifier/challenge pair RFC 7636 compliance.</li>
 *   <li><b>Authorize URL</b> — Epic-specific {@code aud} param, {@code launch} param,
 *       {@code code_challenge_method=S256}.</li>
 *   <li><b>FHIR data</b> — reads Patient and Condition from Epic's open sandbox
 *       endpoint using a known sandbox patient FHIR ID.</li>
 *   <li><b>Token response shape</b> — documented via manual LaunchPad test
 *       (see instructions below).</li>
 * </ul>
 *
 * <h3>Automated vs manual tests</h3>
 * Layers 1–4 are automated and run headlessly.
 * The full OAuth2 code exchange (layer 5) requires a browser — use the
 * LaunchPad manual test described in the {@code @manual} methods below.
 *
 * <h3>Running automated tests</h3>
 * <pre>
 *   export EPIC_CLIENT_ID=your-client-id
 *   mvn failsafe:integration-test -Pepic
 * </pre>
 *
 * <h3>Running the full manual browser test</h3>
 * <pre>
 *   mvn spring-boot:run -Dspring-boot.run.profiles=epic
 *   # Open https://open.epic.com/launchpad in your browser
 *   # Select "SMART EHR Launch" → pick any sandbox patient → enter:
 *   #   Launch URL: http://localhost:8080/launch
 *   # Click Launch — your browser will complete the full SMART handshake
 *   # You should land on http://localhost:8080/ with a valid session
 *   # Then: curl http://localhost:8080/api/patient
 * </pre>
 *
 * <h3>Epic sandbox endpoints</h3>
 * <pre>
 *   FHIR R4 base: https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4
 *   Discovery:    {FHIR base}/.well-known/smart-configuration
 *   Open FHIR:    https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4
 *                 (open endpoint — no auth required for read)
 *   LaunchPad:    https://open.epic.com/launchpad
 * </pre>
 */
@Tag("epic")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("epic")
class EpicSandboxIT {

    /**
     * Epic non-production FHIR base URL.
     * This is the ISS Epic will send in the ?iss= param during EHR launch.
     */
    private static final String EPIC_ISS =
            "https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4";

    /**
     * Known Epic sandbox patient — "Camila Lopez" (pre-loaded in the Epic sandbox).
     * This ID is stable across sandbox resets.
     * Source: https://fhir.epic.com/Documentation#patientlist
     */
    private static final String SANDBOX_PATIENT_ID = "erXuFYUfucBZaryVksYEcMg3";

    @Autowired SmartDiscoveryService discoveryService;
    @Autowired PkceHelper pkceHelper;
    @Autowired SmartAuthRequestBuilder authRequestBuilder;
    @Autowired FhirClientFactory fhirClientFactory;

    @Value("${smart.epic.client-id}")
    private String clientId;

    @Value("${smart.epic.redirect-uri}")
    private String redirectUri;

    @BeforeEach
    void requireClientId() {
        // Fail fast with a clear message if EPIC_CLIENT_ID was not set.
        // Without this, tests fail with a confusing 401 from Epic.
        assertThat(clientId)
                .as("EPIC_CLIENT_ID env var must be set to run Epic integration tests")
                .isNotBlank()
                .isNotEqualTo("your-non-production-client-id");
    }

    // ── Layer 1: Epic discovery ───────────────────────────────────────────────

    @Test
    void epicDiscovery_fetchesRealConfiguration() {
        SmartConfiguration config = discoveryService.discover(EPIC_ISS);

        assertThat(config.authorizationEndpoint())
                .isNotBlank()
                .startsWith("https://fhir.epic.com");

        assertThat(config.tokenEndpoint())
                .isNotBlank()
                .startsWith("https://fhir.epic.com");
    }

    @Test
    void epicDiscovery_advertisesEhrLaunch() {
        SmartConfiguration config = discoveryService.discover(EPIC_ISS);
        assertThat(config.supportsEhrLaunch())
                .as("Epic must advertise launch-ehr in capabilities")
                .isTrue();
    }

    @Test
    void epicDiscovery_advertisesPkceS256() {
        SmartConfiguration config = discoveryService.discover(EPIC_ISS);
        assertThat(config.supportsPkceS256())
                .as("Epic must support S256 PKCE — plain method not accepted")
                .isTrue();
    }

    // ── Layer 2: PKCE ─────────────────────────────────────────────────────────

    @Test
    void pkce_satisfiesRfc7636() {
        PkceParameters pkce = pkceHelper.generate();

        assertThat(pkce.codeVerifier().length()).isBetween(43, 128);
        assertThat(pkce.codeVerifier()).matches("[A-Za-z0-9\\-_]+");
        assertThat(pkce.codeChallenge()).hasSize(43);

        // Epic server-side: SHA-256(verifier) must == challenge
        assertThat(pkceHelper.computeChallenge(pkce.codeVerifier()))
                .isEqualTo(pkce.codeChallenge());
    }

    // ── Layer 3: Authorize URL — Epic-specific params ─────────────────────────

    @Test
    void authorizeUrl_containsEpicRequiredParams() {
        SmartConfiguration config = discoveryService.discover(EPIC_ISS);

        SmartLaunchSession launchSession = SmartLaunchSession.of(
                EPIC_ISS,
                "test-launch-token",
                "test-state-nonce",
                config.authorizationEndpoint(),
                config.tokenEndpoint(),
                List.of("launch", "openid", "patient/Patient.rs")
        );

        MockHttpSession mockSession = new MockHttpSession();
        String authorizeUrl = authRequestBuilder.buildAuthorizeUrl(launchSession, mockSession);

        // Standard OAuth2
        assertThat(authorizeUrl).contains("response_type=code");
        assertThat(authorizeUrl).contains("client_id=" + clientId);
        assertThat(authorizeUrl).contains("state=test-state-nonce");

        // Epic-specific — these are the params that distinguish Epic from generic OAuth2
        assertThat(authorizeUrl)
                .as("aud param must equal the ISS — Epic validates this server-side")
                .contains("aud=");
        assertThat(authorizeUrl)
                .as("launch param carries the EHR context token")
                .contains("launch=test-launch-token");

        // PKCE — Epic requires S256, rejects plain
        assertThat(authorizeUrl).contains("code_challenge_method=S256");
        assertThat(authorizeUrl).contains("code_challenge=");
    }

    @Test
    void authorizeUrl_startsWithEpicAuthEndpoint() {
        SmartConfiguration config = discoveryService.discover(EPIC_ISS);

        SmartLaunchSession launchSession = SmartLaunchSession.of(
                EPIC_ISS, "launch", "state",
                config.authorizationEndpoint(),
                config.tokenEndpoint(),
                List.of("launch", "openid")
        );

        String url = authRequestBuilder.buildAuthorizeUrl(launchSession, new MockHttpSession());
        assertThat(url).startsWith(config.authorizationEndpoint());
    }

    // ── Layer 4: FHIR data — Epic open sandbox endpoint ───────────────────────

    @Test
    void fhirClient_readsKnownEpicSandboxPatient() {
        // Epic's sandbox has an open (no-auth) FHIR endpoint for read operations.
        // We use a synthetic token — Epic ignores it on the open endpoint.
        SmartLaunchContext ctx = new SmartLaunchContext(
                "sandbox-no-auth-needed",
                SANDBOX_PATIENT_ID, null, EPIC_ISS, true,
                "launch openid patient/Patient.rs",
                Instant.now().plusSeconds(3600), null
        );

        Patient patient = fhirClientFactory.create(ctx)
                .read().resource(Patient.class)
                .withId(SANDBOX_PATIENT_ID).execute();

        assertThat(patient).isNotNull();
        assertThat(patient.getIdElement().getIdPart()).isEqualTo(SANDBOX_PATIENT_ID);
        assertThat(patient.getName()).isNotEmpty();
    }

    @Test
    void fhirClient_patientHasRequiredDemographics() {
        SmartLaunchContext ctx = new SmartLaunchContext(
                "sandbox-no-auth-needed",
                SANDBOX_PATIENT_ID, null, EPIC_ISS, true,
                "launch openid patient/Patient.rs",
                Instant.now().plusSeconds(3600), null
        );

        Patient patient = fhirClientFactory.create(ctx)
                .read().resource(Patient.class)
                .withId(SANDBOX_PATIENT_ID).execute();

        // Epic sandbox patients have full demographics
        assertThat(patient.getNameFirstRep().getFamily()).isNotBlank();
        assertThat(patient.getBirthDate()).isNotNull();
        assertThat(patient.getGender()).isNotNull();
    }

    @Test
    void fhirClient_searchesConditionsForSandboxPatient() {
        SmartLaunchContext ctx = new SmartLaunchContext(
                "sandbox-no-auth-needed",
                SANDBOX_PATIENT_ID, null, EPIC_ISS, true,
                "launch openid patient/Condition.rs",
                Instant.now().plusSeconds(3600), null
        );

        Bundle bundle = fhirClientFactory.create(ctx)
                .search().forResource(Condition.class)
                .where(Condition.PATIENT.hasId(SANDBOX_PATIENT_ID))
                .returnBundle(Bundle.class).execute();

        // Epic sandbox patient Camila Lopez has conditions pre-loaded
        assertThat(bundle).isNotNull();
        assertThat(bundle.getEntry()).isNotEmpty();
    }

    // ── Layer 5: Manual browser test instructions ─────────────────────────────

    /**
     * MANUAL TEST — not automated (requires browser).
     *
     * This is the checklist for the full EHR launch flow.
     * Run it once after getting your Epic client ID, then before any production
     * submission. It exercises every class from Task 1 through Task 9.
     *
     * <pre>
     * SETUP
     *   [ ] export EPIC_CLIENT_ID=your-non-production-client-id
     *   [ ] mvn spring-boot:run -Dspring-boot.run.profiles=epic
     *   [ ] App is running at http://localhost:8080
     *
     * STEP 1: EHR Launch
     *   [ ] Open https://open.epic.com/launchpad
     *   [ ] Select "SMART EHR Launch" tab
     *   [ ] Launch URL: http://localhost:8080/launch
     *   [ ] Select a test patient (e.g. "Camila Lopez")
     *   [ ] Click Launch
     *   [ ] Expected: browser redirected to http://localhost:8080/launch?iss=...&launch=...
     *
     * STEP 2: Discovery + PKCE + Authorize redirect
     *   [ ] App log shows: "Fetching SMART configuration from ISS"
     *   [ ] App log shows: "PKCE generated and stored in session"
     *   [ ] App log shows: "Redirecting to authorize endpoint"
     *   [ ] Browser redirected to Epic's authorize page
     *
     * STEP 3: Epic authorization (EHR auto-approves for sandbox)
     *   [ ] Epic redirects back to http://localhost:8080/callback?code=...&state=...
     *
     * STEP 4: Token exchange
     *   [ ] App log shows: "Exchanging authorization code at token endpoint"
     *   [ ] App log shows: "Token exchange successful — patient=eXXXX"
     *   [ ] App log shows: "Launch context extracted"
     *   [ ] Browser redirected to http://localhost:8080/
     *
     * STEP 5: FHIR data access
     *   [ ] curl http://localhost:8080/api/patient
     *         Expected: JSON with patient name, birthDate, gender
     *   [ ] curl http://localhost:8080/api/conditions
     *         Expected: JSON array of conditions (may be empty for some patients)
     *   [ ] curl http://localhost:8080/api/medications
     *         Expected: JSON array of medication requests
     *   [ ] curl http://localhost:8080/api/summary
     *         Expected: patientId, encounterId (if bound), grantedScopes, patient, conditions, medications
     *
     * STEP 6: Token refresh (wait 60s, then):
     *   [ ] App log shows: "Token nearing expiry" if within 120s buffer
     *         OR token is still fresh (no refresh log) — both are correct
     *
     * STEP 7: Session expiry
     *   [ ] Wait for session timeout (30 min) or invalidate manually
     *   [ ] curl http://localhost:8080/api/patient
     *         Expected: HTTP 401 Unauthorized
     * </pre>
     */
    @Test
    void manualTest_documentedChecklist() {
        // This test always passes — it's documentation, not automation.
        // See the Javadoc above for the manual test checklist.
        assertThat(true).isTrue();
    }
}
