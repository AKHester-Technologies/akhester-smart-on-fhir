package com.akhester.smartfhir.client.fhir;

import ca.uhn.fhir.rest.client.api.IGenericClient;
import com.akhester.smartfhir.client.context.SmartContextExtractor;
import com.akhester.smartfhir.client.context.SmartLaunchContext;
import com.akhester.smartfhir.client.oidc.UserProfile;
import jakarta.servlet.http.HttpSession;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Condition;
import org.hl7.fhir.r4.model.MedicationRequest;
import org.hl7.fhir.r4.model.Patient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * REST API controller — exposes patient FHIR data, session context, and user
 * identity for the authenticated SMART launch session.
 *
 * <h3>Endpoints</h3>
 * <ul>
 *   <li>{@code GET /api/session}     — launch mode, patient/encounter IDs, granted scopes,
 *                                       needPatientBanner. Safe to call before patient is selected.</li>
 *   <li>{@code GET /api/me}          — authenticated clinician's OIDC profile (subject, name,
 *                                       fhirUser). Returns 404 if openid scope not granted.</li>
 *   <li>{@code GET /api/patient}     — in-context patient demographics.</li>
 *   <li>{@code GET /api/conditions}  — active problem list.</li>
 *   <li>{@code GET /api/medications} — current medication requests.</li>
 *   <li>{@code GET /api/summary}     — combined view of all available data.</li>
 * </ul>
 *
 * <h3>Standalone launch note</h3>
 * For standalone launch, {@code patientId} may be null until the user selects
 * a patient through the auth server's patient picker. {@code /api/session} is
 * always safe. {@code /api/patient}, {@code /api/conditions}, {@code /api/medications}
 * return 400 with a clear message when no patient context is available.
 */
@RestController
@RequestMapping("/api")
public class PatientDataController {

    private static final Logger log = LoggerFactory.getLogger(PatientDataController.class);

    private final FhirClientFactory clientFactory;
    private final SmartContextExtractor contextExtractor;

    public PatientDataController(FhirClientFactory clientFactory,
                                  SmartContextExtractor contextExtractor) {
        this.clientFactory    = clientFactory;
        this.contextExtractor = contextExtractor;
    }

    /**
     * Returns the current session state — always safe to call, even for
     * standalone launch before a patient has been selected.
     *
     * <p>Use this as the first call from your frontend after the launch redirect
     * to determine launch mode and which UI panels to render.</p>
     */
    @GetMapping("/session")
    public Map<String, Object> session(HttpSession session) {
        SmartLaunchContext ctx = requireContext(session);
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("launchMode",      ctx.patientId() != null ? "ehr" : "standalone");
        result.put("patientId",       ctx.patientId());           // null for standalone
        result.put("encounterId",     ctx.hasEncounter() ? ctx.encounterId() : null);
        result.put("needPatientBanner", ctx.needPatientBanner());
        result.put("grantedScopes",   ctx.scope());
        result.put("hasUserProfile",  ctx.hasUserProfile());
        result.put("tokenExpiresAt",  ctx.expiresAt().toString());
        return result;
    }

    /**
     * Returns the authenticated clinician's OIDC profile.
     *
     * <p>Requires {@code openid} scope. Returns 404 if the id_token was absent
     * or failed validation (Epic omits it in some configurations).</p>
     *
     * <p>The {@code fhirUser} field, when present, is a FHIR reference
     * (e.g. {@code Practitioner/eXXX}) that can be used to fetch the
     * Practitioner resource for the logged-in clinician.</p>
     */
    @GetMapping("/me")
    public Map<String, Object> me(HttpSession session) {
        SmartLaunchContext ctx = requireContext(session);

        if (!ctx.hasUserProfile()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "No user profile available — ensure 'openid' scope was granted "
                    + "and the id_token passed validation");
        }

        var profile = ctx.userProfile();
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("subject",     profile.subject());
        result.put("displayName", profile.displayName());
        result.put("fhirUser",    profile.hasFhirUser() ? profile.fhirUser() : null);
        result.put("issuer",      profile.issuer());
        return result;
    }

    /**
     * Returns the in-context patient's demographics.
     * Requires scope: {@code patient/Patient.rs}
     */
    @GetMapping("/patient")
    public Map<String, Object> patient(HttpSession session) {
        SmartLaunchContext ctx = requireContext(session);
        requirePatientContext(ctx);
        requireScope(ctx, "patient/Patient.rs");

        IGenericClient client = clientFactory.create(ctx);

        log.info("Fetching Patient/{}", ctx.patientId());
        Patient patient = client.read()
                .resource(Patient.class)
                .withId(ctx.patientId())
                .execute();

        return Map.of(
                "id",            patient.getIdElement().getIdPart(),
                "name",          extractName(patient),
                "birthDate",     patient.getBirthDateElement().getValueAsString(),
                "gender",        patient.getGender() != null
                                         ? patient.getGender().toCode() : "unknown",
                "patientBanner", ctx.needPatientBanner()
        );
    }

    /**
     * Returns the in-context patient's active conditions.
     * Requires scope: {@code patient/Condition.rs}
     */
    @GetMapping("/conditions")
    public List<Map<String, Object>> conditions(HttpSession session) {
        SmartLaunchContext ctx = requireContext(session);
        requirePatientContext(ctx);
        requireScope(ctx, "patient/Condition.rs");

        IGenericClient client = clientFactory.create(ctx);

        log.info("Fetching Conditions for patient/{}", ctx.patientId());
        Bundle bundle = client.search()
                .forResource(Condition.class)
                .where(Condition.PATIENT.hasId(ctx.patientId()))
                .where(Condition.CLINICAL_STATUS.exactly().code("active"))
                .returnBundle(Bundle.class)
                .execute();

        return bundle.getEntry().stream()
                .filter(e -> e.getResource() instanceof Condition)
                .map(e -> (Condition) e.getResource())
                .map(c -> {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("id",      c.getIdElement().getIdPart());
                    item.put("code",    c.getCode().getCodingFirstRep().getCode());
                    item.put("display", c.getCode().getCodingFirstRep().getDisplay());
                    item.put("status",  c.getClinicalStatus().getCodingFirstRep().getCode());
                    return item;
                })
                .toList();
    }

    /**
     * Returns the in-context patient's active medication requests.
     * Requires scope: {@code patient/MedicationRequest.rs}
     */
    @GetMapping("/medications")
    public List<Map<String, Object>> medications(HttpSession session) {
        SmartLaunchContext ctx = requireContext(session);
        requirePatientContext(ctx);
        requireScope(ctx, "patient/MedicationRequest.rs");

        IGenericClient client = clientFactory.create(ctx);

        log.info("Fetching MedicationRequests for patient/{}", ctx.patientId());
        Bundle bundle = client.search()
                .forResource(MedicationRequest.class)
                .where(MedicationRequest.PATIENT.hasId(ctx.patientId()))
                .where(MedicationRequest.STATUS.exactly().code("active"))
                .returnBundle(Bundle.class)
                .execute();

        return bundle.getEntry().stream()
                .filter(e -> e.getResource() instanceof MedicationRequest)
                .map(e -> (MedicationRequest) e.getResource())
                .map(m -> {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("id", m.getIdElement().getIdPart());
                    String medName;
                    if (m.hasMedicationCodeableConcept()) {
                        medName = m.getMedicationCodeableConcept()
                                .getCodingFirstRep().getDisplay();
                    } else if (m.hasMedicationReference()) {
                        medName = m.getMedicationReference().getDisplay();
                    } else {
                        medName = "Unknown medication";
                    }
                    item.put("medication", medName);
                    item.put("status",     m.getStatus().toCode());
                    item.put("intent",     m.getIntent().toCode());
                    return item;
                })
                .toList();
    }

    /**
     * Returns a combined summary — session context plus all available
     * FHIR data for which scopes were granted.
     * Safe for both EHR launch (full data) and standalone (session only until patient selected).
     */
    @GetMapping("/summary")
    public Map<String, Object> summary(HttpSession session) {
        SmartLaunchContext ctx = requireContext(session);
        Map<String, Object> result = new LinkedHashMap<>();

        // Always-present session fields
        result.put("launchMode",      ctx.patientId() != null ? "ehr" : "standalone");
        result.put("patientId",       ctx.patientId());
        result.put("encounterId",     ctx.hasEncounter() ? ctx.encounterId() : null);
        result.put("needPatientBanner", ctx.needPatientBanner());
        result.put("grantedScopes",   ctx.scope());

        // User profile — present when openid scope granted and id_token validated
        if (ctx.hasUserProfile()) {
            result.put("user", Map.of(
                    "subject",     ctx.userProfile().subject(),
                    "displayName", ctx.userProfile().displayName(),
                    "fhirUser",    ctx.userProfile().hasFhirUser()
                            ? ctx.userProfile().fhirUser() : null
            ));
        }

        // FHIR data — only when patient context available and scope granted
        if (ctx.patientId() != null) {
            if (ctx.hasScope("patient/Patient.rs")) {
                result.put("patient", patient(session));
            }
            if (ctx.hasScope("patient/Condition.rs")) {
                result.put("conditions", conditions(session));
            }
            if (ctx.hasScope("patient/MedicationRequest.rs")) {
                result.put("medications", medications(session));
            }
        }

        return result;
    }

    // ── private helpers ───────────────────────────────────────────────────────

    private SmartLaunchContext requireContext(HttpSession session) {
        SmartLaunchContext ctx = contextExtractor.retrieve(session);
        if (ctx == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "No active SMART session — please launch from the EHR");
        }
        if (ctx.isTokenExpired()) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED,
                    "SMART session expired — please re-launch from the EHR");
        }
        return ctx;
    }

    /**
     * Ensures a patient is in context — returns 400 for standalone launch
     * before a patient has been selected, rather than a NullPointerException
     * deep inside the HAPI FHIR client.
     */
    private void requirePatientContext(SmartLaunchContext ctx) {
        if (ctx.patientId() == null || ctx.patientId().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "No patient in context — for standalone launch, "
                    + "the user must select a patient before FHIR data can be accessed");
        }
    }

    private void requireScope(SmartLaunchContext ctx, String scope) {
        if (!ctx.hasScope(scope)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "Scope not granted: " + scope
                    + " — add it to smart.epic.scopes in application.yml");
        }
    }

    private String extractName(Patient patient) {
        if (patient.getName().isEmpty()) return "Unknown";
        var name = patient.getNameFirstRep();
        String family = name.getFamily() != null ? name.getFamily() : "";
        String given  = name.getGivenAsSingleString();
        return (given + " " + family).trim();
    }
}
