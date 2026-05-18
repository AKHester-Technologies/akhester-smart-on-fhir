package com.akhester.smartfhir.client;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Minimal health endpoint — confirms the application started and
 * the SMART config bound correctly.
 *
 * GET /health → {"status":"UP","app":"smart-fhir-client"}
 *
 * The real health check (Actuator) is at /actuator/health.
 * This one is intentionally public and simple for smoke-testing.
 */
@RestController
public class HealthController {

    private final EpicProperties epic;

    public HealthController(EpicProperties epic) {
        this.epic = epic;
    }

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of(
                "status", "UP",
                "app", "smart-fhir-client",
                "epicClientId", maskClientId(epic.clientId())
                // redirectUri and scopes intentionally omitted — enumeration risk
        );
    }

    /** Show only the first 8 chars of the client ID in health output. */
    private String maskClientId(String clientId) {
        if (clientId == null || clientId.length() <= 8) return "***";
        return clientId.substring(0, 8) + "...";
    }
}
