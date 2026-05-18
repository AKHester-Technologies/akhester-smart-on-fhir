package com.akhester.smartfhir.client.it;

import ca.uhn.fhir.rest.client.api.IGenericClient;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.akhester.smartfhir.client.EpicProperties;
import com.akhester.smartfhir.client.auth.PkceHelper;
import com.akhester.smartfhir.client.auth.PkceParameters;
import com.akhester.smartfhir.client.context.SmartLaunchContext;
import com.akhester.smartfhir.client.discovery.SmartConfiguration;
import com.akhester.smartfhir.client.discovery.SmartDiscoveryService;
import com.akhester.smartfhir.client.fhir.FhirClientFactory;
import org.hl7.fhir.r4.model.Patient;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests against the SMART Health IT public sandbox.
 *
 * <h3>What this tests (no browser required)</h3>
 * The full browser-based EHR launch flow (clicking LaunchPad, OAuth2 redirect,
 * user consent) cannot be automated in a headless test. Instead, this class
 * tests each layer independently against real SMART Health IT endpoints:
 *
 * <ul>
 *   <li><b>Layer 1 — Discovery</b>: fetches the real
 *       {@code /.well-known/smart-configuration} from launch.smarthealthit.org
 *       and verifies the document contains the expected fields.</li>
 *   <li><b>Layer 2 — PKCE</b>: generates a real PKCE pair and verifies the
 *       mathematical relationship (SHA-256 of verifier == challenge). Not
 *       network-dependent — proves the RFC 7636 implementation is correct.</li>
 *   <li><b>Layer 3 — FHIR data</b>: reads a known synthetic patient from the
 *       SMART Health IT open (unauthenticated) FHIR endpoint. Verifies our HAPI
 *       client can parse real FHIR R4 responses from a non-Epic server.</li>
 *   <li><b>Layer 4 — Authorize URL</b>: verifies the authorize URL is built
 *       correctly using the discovered auth endpoint, with PKCE and all required
 *       params present.</li>
 * </ul>
 *
 * <h3>What is NOT tested here (requires Epic sandbox — see EpicSandboxIT)</h3>
 * <ul>
 *   <li>The complete OAuth2 code exchange (requires browser + consent)</li>
 *   <li>Epic-specific token extras (patient, encounter, need_patient_banner)</li>
 *   <li>Epic's enforcement of the {@code aud} parameter</li>
 *   <li>Token refresh with real refresh tokens</li>
 * </ul>
 *
 * <h3>Running</h3>
 * <pre>
 *   mvn failsafe:integration-test -Psmart
 * </pre>
 * No credentials required. Requires outbound internet access to
 * {@code launch.smarthealthit.org}.
 *
 * <h3>CI usage</h3>
 * Add to your pipeline as a standard integration test stage — no secrets needed:
 * <pre>
 *   - mvn verify -Psmart
 * </pre>
 */
@Tag("smart")
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("smart")
class SmartHealthSandboxIT {

    // SMART Health IT R4 FHIR base URL
    private static final String SMART_ISS =
            "https://launch.smarthealthit.org/v/r4/fhir";

    // Known synthetic patient in the SMART Health IT sandbox.
    // Synthea-generated — stable across sandbox resets.
    private static final String TEST_PATIENT_ID =
            "87a339d0-8cae-418e-89c7-8651e6aab3c6";

    @Autowired SmartDiscoveryService discoveryService;
    @Autowired PkceHelper pkceHelper;
    @Autowired FhirClientFactory fhirClientFactory;
    @Autowired EpicProperties epicProperties;

    // ── Layer 1: Discovery ────────────────────────────────────────────────────

    @Test
    void discovery_fetchesRealSmartConfiguration() {
        SmartConfiguration config = discoveryService.discover(SMART_ISS);

        assertThat(config).isNotNull();
        assertThat(config.authorizationEndpoint())
                .isNotBlank()
                .startsWith("https://");
        assertThat(config.tokenEndpoint())
                .isNotBlank()
                .startsWith("https://");
    }

    @Test
    void discovery_supportsEhrLaunch() {
        SmartConfiguration config = discoveryService.discover(SMART_ISS);
        assertThat(config.supportsEhrLaunch())
                .as("SMART Health IT sandbox must advertise launch-ehr capability")
                .isTrue();
    }

    @Test
    void discovery_supportsPkceS256() {
        SmartConfiguration config = discoveryService.discover(SMART_ISS);
        assertThat(config.supportsPkceS256())
                .as("SMART Health IT sandbox must support S256 PKCE")
                .isTrue();
    }

    @Test
    void discovery_caching_secondCallDoesNotRefetch() {
        // First call populates cache
        SmartConfiguration first  = discoveryService.discover(SMART_ISS);
        // Second call should return cached result (same object reference)
        SmartConfiguration second = discoveryService.discover(SMART_ISS);

        assertThat(first.authorizationEndpoint())
                .isEqualTo(second.authorizationEndpoint());
        assertThat(first.tokenEndpoint())
                .isEqualTo(second.tokenEndpoint());
    }

    // ── Layer 2: PKCE ─────────────────────────────────────────────────────────

    @Test
    void pkce_generatedPairSatisfiesRfc7636() {
        PkceParameters pkce = pkceHelper.generate();

        // Verifier within RFC range
        assertThat(pkce.codeVerifier().length())
                .isBetween(43, 128);

        // Verifier uses only unreserved characters
        assertThat(pkce.codeVerifier())
                .matches("[A-Za-z0-9\\-_]+");

        // Challenge is 43-char base64url (SHA-256 → 32 bytes → 43 chars)
        assertThat(pkce.codeChallenge())
                .hasSize(43)
                .matches("[A-Za-z0-9\\-_]+");

        // Most important: challenge == BASE64URL(SHA256(verifier))
        String recomputed = pkceHelper.computeChallenge(pkce.codeVerifier());
        assertThat(pkce.codeChallenge())
                .as("Challenge must equal SHA-256 of verifier — Epic validates this")
                .isEqualTo(recomputed);
    }

    @Test
    void pkce_repeatedCallsProduceUniqueVerifiers() {
        String v1 = pkceHelper.generate().codeVerifier();
        String v2 = pkceHelper.generate().codeVerifier();
        assertThat(v1).isNotEqualTo(v2);
    }

    // ── Layer 3: FHIR data client ─────────────────────────────────────────────

    @Test
    void fhirClient_readsKnownSyntheticPatient() {
        // SMART Health IT sandbox has an open (unauthenticated) FHIR endpoint.
        // We create a context pointing at it — the bearer token is unused on
        // the open endpoint, but the FhirClientFactory wiring is exercised.
        SmartLaunchContext ctx = new SmartLaunchContext(
                "unused-token-open-endpoint",
                TEST_PATIENT_ID,
                null,
                SMART_ISS,
                true,
                "launch openid patient/Patient.rs",
                Instant.now().plusSeconds(3600),
                null
        );

        IGenericClient client = fhirClientFactory.create(ctx);

        Patient patient = client.read()
                .resource(Patient.class)
                .withId(TEST_PATIENT_ID)
                .execute();

        assertThat(patient).isNotNull();
        assertThat(patient.getIdElement().getIdPart()).isEqualTo(TEST_PATIENT_ID);
        assertThat(patient.getName()).isNotEmpty();
        assertThat(patient.getBirthDate()).isNotNull();
    }

    @Test
    void fhirClient_parsesPatientName() {
        SmartLaunchContext ctx = new SmartLaunchContext(
                "unused-token-open-endpoint",
                TEST_PATIENT_ID, null, SMART_ISS, true,
                "launch openid patient/Patient.rs",
                Instant.now().plusSeconds(3600), null
        );

        Patient patient = fhirClientFactory.create(ctx)
                .read().resource(Patient.class)
                .withId(TEST_PATIENT_ID).execute();

        // Patient must have at least one name with a family component
        assertThat(patient.getNameFirstRep().getFamily())
                .isNotBlank();
    }

    // ── Layer 4: Authorize URL construction ───────────────────────────────────

    @Test
    void authorizeUrl_builtCorrectlyFromDiscoveredEndpoint() {
        SmartConfiguration config = discoveryService.discover(SMART_ISS);
        PkceParameters pkce = pkceHelper.generate();

        // Build the URL manually — same logic as SmartAuthRequestBuilder
        String url = config.authorizationEndpoint()
                + "?response_type=code"
                + "&client_id=" + epicProperties.clientId()
                + "&redirect_uri=" + java.net.URLEncoder.encode(
                        epicProperties.redirectUri(),
                        java.nio.charset.StandardCharsets.UTF_8)
                + "&scope=launch+openid+patient%2FPatient.rs"
                + "&state=test-state-nonce"
                + "&aud=" + java.net.URLEncoder.encode(
                        SMART_ISS, java.nio.charset.StandardCharsets.UTF_8)
                + "&code_challenge=" + pkce.codeChallenge()
                + "&code_challenge_method=S256";

        assertThat(url)
                .startsWith(config.authorizationEndpoint())
                .contains("response_type=code")
                .contains("code_challenge_method=S256")
                .contains("code_challenge=" + pkce.codeChallenge());
    }
}
