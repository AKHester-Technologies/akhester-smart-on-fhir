package com.akhester.smartfhir.client.ui;

import com.akhester.smartfhir.client.context.SmartContextExtractor;
import com.akhester.smartfhir.client.context.SmartLaunchContext;
import com.akhester.smartfhir.client.fhir.FhirClientFactory;
import ca.uhn.fhir.rest.client.api.IGenericClient;
import ca.uhn.fhir.rest.server.exceptions.BaseServerResponseException;
import jakarta.servlet.http.HttpSession;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Condition;
import org.hl7.fhir.r4.model.MedicationRequest;
import org.hl7.fhir.r4.model.Patient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Serves the Thymeleaf HTML pages for the SMART FHIR client UI.
 *
 * <h3>Design</h3>
 * Each handler fetches data from Epic via HAPI FHIR, packs it into a Thymeleaf
 * model, and returns the template name. FHIR errors are caught and surfaced as
 * user-visible error messages rather than stack traces.
 *
 * <h3>Session model</h3>
 * Every page gets a {@code session} model object containing the safe-to-display
 * subset of {@link SmartLaunchContext} (no access token). Templates use this
 * to render the patient banner, nav user, scope list, etc.
 */
@Controller
public class UiController {

    private static final Logger log = LoggerFactory.getLogger(UiController.class);

    private final SmartContextExtractor contextExtractor;
    private final FhirClientFactory fhirClientFactory;

    public UiController(SmartContextExtractor contextExtractor,
                        FhirClientFactory fhirClientFactory) {
        this.contextExtractor  = contextExtractor;
        this.fhirClientFactory = fhirClientFactory;
    }

    // ── Dashboard ─────────────────────────────────────────────────────────────

    @GetMapping("/")
    public String index(HttpSession session, Model model) {
        SmartLaunchContext ctx = contextExtractor.retrieve(session);
        if (ctx == null) {
            return "index"; // unauthenticated — template shows launch instructions
        }

        model.addAttribute("session", buildSessionModel(ctx));

        // User profile
        if (ctx.hasUserProfile()) {
            model.addAttribute("user", Map.of(
                    "displayName", ctx.userProfile().displayName(),
                    "subject",     ctx.userProfile().subject(),
                    "fhirUser",    ctx.userProfile().hasFhirUser()
                            ? ctx.userProfile().fhirUser() : null
            ));
        }

        // Counts for stat cards — fetch quietly, don't fail the page if unavailable
        if (ctx.patientId() != null) {
            if (ctx.hasScope("patient/Condition.rs")) {
                try {
                    IGenericClient client = fhirClientFactory.create(ctx);
                    Bundle b = client.search().forResource(Condition.class)
                            .where(Condition.PATIENT.hasId(ctx.patientId()))
                            .where(Condition.CLINICAL_STATUS.exactly().code("active"))
                            .returnBundle(Bundle.class).execute();
                    model.addAttribute("conditionCount", b.getTotal());
                } catch (Exception e) {
                    log.debug("Could not fetch condition count: {}", e.getMessage());
                }
            }
            if (ctx.hasScope("patient/MedicationRequest.rs")) {
                try {
                    IGenericClient client = fhirClientFactory.create(ctx);
                    Bundle b = client.search().forResource(MedicationRequest.class)
                            .where(MedicationRequest.PATIENT.hasId(ctx.patientId()))
                            .where(MedicationRequest.STATUS.exactly().code("active"))
                            .returnBundle(Bundle.class).execute();
                    model.addAttribute("medicationCount", b.getTotal());
                } catch (Exception e) {
                    log.debug("Could not fetch medication count: {}", e.getMessage());
                }
            }
        }

        return "index";
    }

    // ── Patient page ──────────────────────────────────────────────────────────

    @GetMapping("/patient")
    public String patientPage(HttpSession session, Model model) {
        SmartLaunchContext ctx = contextExtractor.retrieve(session);
        if (ctx == null) return "redirect:/";

        model.addAttribute("session", buildSessionModel(ctx));

        if (ctx.patientId() == null) {
            model.addAttribute("error", "No patient in context (standalone launch — select a patient first)");
            return "patient";
        }

        if (!ctx.hasScope("patient/Patient.rs")) {
            return "patient"; // template shows scope-required message
        }

        try {
            IGenericClient client = fhirClientFactory.create(ctx);
            Patient patient = client.read().resource(Patient.class)
                    .withId(ctx.patientId()).execute();

            String name   = extractName(patient);
            String dob    = patient.getBirthDateElement().getValueAsString();
            String gender = patient.getGender() != null
                    ? capitalize(patient.getGender().toCode()) : null;

            // Update session model so the patient banner renders the fetched name
            @SuppressWarnings("unchecked")
            Map<String, Object> sessionModel =
                    (Map<String, Object>) model.getAttribute("session");
            if (sessionModel != null) {
                sessionModel.put("patientName",   name);
                sessionModel.put("patientDob",    dob);
                sessionModel.put("patientGender", gender);
            }

            model.addAttribute("patient", Map.of(
                    "id",            patient.getIdElement().getIdPart(),
                    "name",          name,
                    "birthDate",     dob,
                    "gender",        gender != null ? gender : "unknown",
                    "patientBanner", ctx.needPatientBanner()
            ));

        } catch (BaseServerResponseException e) {
            model.addAttribute("error", "FHIR error fetching patient: " + e.getMessage());
            log.error("FHIR error on patient page: {}", e.getMessage());
        }

        return "patient";
    }

    // ── Conditions page ───────────────────────────────────────────────────────

    @GetMapping("/conditions")
    public String conditionsPage(HttpSession session, Model model) {
        SmartLaunchContext ctx = contextExtractor.retrieve(session);
        if (ctx == null) return "redirect:/";

        model.addAttribute("session", buildSessionModel(ctx));

        if (ctx.patientId() == null) {
            model.addAttribute("error", "No patient in context");
            return "conditions";
        }

        if (!ctx.hasScope("patient/Condition.rs")) {
            return "conditions";
        }

        try {
            IGenericClient client = fhirClientFactory.create(ctx);
            Bundle bundle = client.search().forResource(Condition.class)
                    .where(Condition.PATIENT.hasId(ctx.patientId()))
                    .where(Condition.CLINICAL_STATUS.exactly().code("active"))
                    .returnBundle(Bundle.class).execute();

            List<Map<String, Object>> conditions = new ArrayList<>();
            for (Bundle.BundleEntryComponent entry : bundle.getEntry()) {
                if (entry.getResource() instanceof Condition c) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("id",      c.getIdElement().getIdPart());
                    item.put("code",    c.getCode().getCodingFirstRep().getCode());
                    item.put("display", c.getCode().getCodingFirstRep().getDisplay());
                    item.put("status",  c.getClinicalStatus().getCodingFirstRep().getCode());
                    conditions.add(item);
                }
            }
            model.addAttribute("conditions", conditions);

        } catch (BaseServerResponseException e) {
            model.addAttribute("error", "FHIR error fetching conditions: " + e.getMessage());
        }

        return "conditions";
    }

    // ── Medications page ──────────────────────────────────────────────────────

    @GetMapping("/medications")
    public String medicationsPage(HttpSession session, Model model) {
        SmartLaunchContext ctx = contextExtractor.retrieve(session);
        if (ctx == null) return "redirect:/";

        model.addAttribute("session", buildSessionModel(ctx));

        if (ctx.patientId() == null) {
            model.addAttribute("error", "No patient in context");
            return "medications";
        }

        if (!ctx.hasScope("patient/MedicationRequest.rs")) {
            return "medications";
        }

        try {
            IGenericClient client = fhirClientFactory.create(ctx);
            Bundle bundle = client.search().forResource(MedicationRequest.class)
                    .where(MedicationRequest.PATIENT.hasId(ctx.patientId()))
                    .where(MedicationRequest.STATUS.exactly().code("active"))
                    .returnBundle(Bundle.class).execute();

            List<Map<String, Object>> medications = new ArrayList<>();
            for (Bundle.BundleEntryComponent entry : bundle.getEntry()) {
                if (entry.getResource() instanceof MedicationRequest m) {
                    Map<String, Object> item = new LinkedHashMap<>();
                    item.put("id",  m.getIdElement().getIdPart());
                    String medName;
                    if (m.hasMedicationCodeableConcept()) {
                        medName = m.getMedicationCodeableConcept().getCodingFirstRep().getDisplay();
                    } else if (m.hasMedicationReference()) {
                        medName = m.getMedicationReference().getDisplay();
                    } else {
                        medName = "Unknown medication";
                    }
                    item.put("medication", medName);
                    item.put("status",     m.getStatus().toCode());
                    item.put("intent",     m.getIntent().toCode());
                    medications.add(item);
                }
            }
            model.addAttribute("medications", medications);

        } catch (BaseServerResponseException e) {
            model.addAttribute("error", "FHIR error fetching medications: " + e.getMessage());
        }

        return "medications";
    }

    // ── private helpers ───────────────────────────────────────────────────────

    /**
     * Builds the safe session model for templates — never includes the access token.
     * patientName/patientDob/patientGender start as null; patientPage() populates
     * them after fetching the Patient resource so the banner can render them.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> buildSessionModel(SmartLaunchContext ctx) {
        Map<String, Object> s = new LinkedHashMap<>();
        s.put("patientId",         ctx.patientId());
        s.put("patientName",       null);   // filled by patientPage after FHIR fetch
        s.put("patientDob",        null);   // filled by patientPage after FHIR fetch
        s.put("patientGender",     null);   // filled by patientPage after FHIR fetch
        s.put("encounterId",       ctx.encounterId());
        s.put("fhirBaseUrl",       ctx.fhirBaseUrl());
        s.put("needPatientBanner", ctx.needPatientBanner());
        s.put("grantedScopes",     ctx.scope());
        s.put("launchMode",        ctx.patientId() != null ? "ehr" : "standalone");
        s.put("hasUserProfile",    ctx.hasUserProfile());
        s.put("tokenExpiresAt",    ctx.expiresAt().toString());
        s.put("tokenExpiresIn",    formatExpiry(ctx.expiresAt()));

        if (ctx.hasUserProfile()) {
            s.put("userName", ctx.userProfile().displayName());
        }

        return s;
    }

    private String formatExpiry(Instant expiresAt) {
        long minLeft = Duration.between(Instant.now(), expiresAt).toMinutes();
        if (minLeft < 1) return "< 1 min";
        if (minLeft < 60) return "in " + minLeft + " min";
        return "in " + (minLeft / 60) + "h " + (minLeft % 60) + "m";
    }

    private String extractName(Patient patient) {
        if (patient.getName().isEmpty()) return "Unknown";
        var name = patient.getNameFirstRep();
        String family = name.getFamily() != null ? name.getFamily() : "";
        String given  = name.getGivenAsSingleString();
        return (given + " " + family).trim();
    }

    private String capitalize(String s) {
        if (s == null || s.isBlank()) return s;
        return Character.toUpperCase(s.charAt(0)) + s.substring(1).toLowerCase();
    }
}
