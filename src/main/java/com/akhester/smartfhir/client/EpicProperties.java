package com.akhester.smartfhir.client;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;

/**
 * Typed binding for the {@code smart.epic.*} block in application.yml.
 *
 * Validated at startup — the app will refuse to start if client-id or
 * redirect-uri are missing, rather than failing silently at first launch.
 *
 * Inject this wherever Epic-specific config is needed:
 * <pre>
 *   public MyService(EpicProperties epic) { ... }
 * </pre>
 */
@Validated
@ConfigurationProperties(prefix = "smart.epic")
public record EpicProperties(

        @NotBlank(message = "smart.epic.client-id must be set (use EPIC_CLIENT_ID env var)")
        String clientId,

        @NotBlank(message = "smart.epic.redirect-uri must be set (use EPIC_REDIRECT_URI env var)")
        String redirectUri,

        @NotEmpty(message = "smart.epic.scopes must contain at least 'launch'")
        List<String> scopes,

        @Min(value = 1, message = "smart.epic.discovery-cache-minutes must be at least 1")
        int discoveryCacheMinutes

) {}
