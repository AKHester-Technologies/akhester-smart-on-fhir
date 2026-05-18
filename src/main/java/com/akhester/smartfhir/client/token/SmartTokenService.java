package com.akhester.smartfhir.client.token;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.akhester.smartfhir.client.EpicProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Exchanges an authorization code for an access token at Epic's token endpoint.
 *
 * <h3>What this sends (RFC 6749 §4.1.3 + RFC 7636 §4.5)</h3>
 * <pre>
 *   POST {token_endpoint}
 *   Content-Type: application/x-www-form-urlencoded
 *
 *   grant_type    = authorization_code
 *   code          = {authorization_code from callback}
 *   redirect_uri  = {must exactly match the one in the authorize request}
 *   client_id     = {your Epic client ID}
 *   code_verifier = {PKCE verifier stored in session during Task 4}
 * </pre>
 *
 * <h3>Why no client_secret?</h3>
 * Epic EHR launch apps registered as "public" clients do not use a
 * client_secret — PKCE replaces it as the proof of authenticity.
 * If you register a "confidential" client (backend services), you would
 * add {@code client_secret} here or switch to JWT client assertion auth.
 *
 * <h3>Why java.net.http.HttpClient again?</h3>
 * Token exchange is one synchronous blocking call per user login.
 * The built-in client is sufficient; no reactive or pooling overhead needed.
 * HAPI FHIR (Task 7) handles the high-frequency FHIR API calls with its
 * own connection pool.
 */
@Service
public class SmartTokenService {

    private static final Logger log = LoggerFactory.getLogger(SmartTokenService.class);

    private final EpicProperties epicProperties;
    private final ObjectMapper objectMapper;
    private final HttpClient http;

    public SmartTokenService(EpicProperties epicProperties, ObjectMapper objectMapper) {
        this.epicProperties = epicProperties;
        this.objectMapper   = objectMapper;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    /**
     * Exchanges an authorization code for tokens.
     *
     * @param tokenEndpoint the token URL from SMART discovery (Task 2)
     * @param authCode      the {@code code} parameter from Epic's callback redirect
     * @param codeVerifier  the PKCE verifier stored in session during Task 4
     * @return parsed and validated {@link SmartTokenResponse}
     * @throws TokenExchangeException on any failure (network, HTTP error, bad JSON, missing fields)
     */
    public SmartTokenResponse exchange(String tokenEndpoint, String authCode, String codeVerifier) {
        if (tokenEndpoint == null || tokenEndpoint.isBlank()) {
            throw new TokenExchangeException(
                    "tokenEndpoint must not be blank — check SmartDiscovery returned a valid token_endpoint");
        }

        log.info("Exchanging authorization code at token endpoint: {}", tokenEndpoint);

        // ── Build form body ───────────────────────────────────────────────────
        // LinkedHashMap preserves insertion order — form body is always in the same
        // sequence across JVM runs, making logs and WireMock recordings predictable.
        Map<String, String> params = new java.util.LinkedHashMap<>();
        params.put("grant_type",    "authorization_code");
        params.put("code",          authCode);
        params.put("redirect_uri",  epicProperties.redirectUri());
        params.put("client_id",     epicProperties.clientId());
        params.put("code_verifier", codeVerifier);  // PKCE — Epic validates SHA-256(verifier)==challenge
        String formBody = buildFormBody(params);

        // ── POST to token endpoint ────────────────────────────────────────────
        HttpRequest request = HttpRequest.newBuilder(URI.create(tokenEndpoint))
                .POST(HttpRequest.BodyPublishers.ofString(formBody))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(15))
                .build();

        HttpResponse<String> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new TokenExchangeException(
                    "Network error during token exchange: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TokenExchangeException(
                    "Token exchange interrupted", e);
        }

        // ── Handle non-200 ────────────────────────────────────────────────────
        if (response.statusCode() != 200) {
            // extractError() truncates and redacts — same output goes to both log and exception.
            String errorDetail = extractError(response.body());
            log.error("Token endpoint returned HTTP {} — {}", response.statusCode(), errorDetail);
            throw new TokenExchangeException(
                    "Token endpoint returned HTTP %d: %s"
                            .formatted(response.statusCode(), errorDetail));
        }

        // ── Parse response ────────────────────────────────────────────────────
        SmartTokenResponse raw;
        try {
            raw = objectMapper.readValue(response.body(), SmartTokenResponse.class);
        } catch (IOException e) {
            throw new TokenExchangeException(
                    "Failed to parse token response JSON: " + e.getMessage(), e);
        }

        // ── Compute derived fields and validate ───────────────────────────────
        SmartTokenResponse tokenResponse = SmartTokenResponse.withComputedExpiry(raw);
        tokenResponse.validate();

        log.info("Token exchange successful — patient={}, expires={}",
                tokenResponse.patient(), tokenResponse.expiresAt());

        return tokenResponse;
    }

    // ── private helpers ───────────────────────────────────────────────────────

    /**
     * Builds a URL-encoded form body from a map of parameters.
     * Each key and value is percent-encoded per RFC 3986.
     */
    private String buildFormBody(Map<String, String> params) {
        return params.entrySet().stream()
                .map(e -> encode(e.getKey()) + "=" + encode(e.getValue()))
                .collect(Collectors.joining("&"));
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /**
     * Attempts to extract the {@code error} or {@code error_description}
     * from an OAuth2 error response body. Falls back to the raw body.
     */
    private String extractError(String body) {
        try {
            var node = objectMapper.readTree(body);
            String desc = node.path("error_description").asText(null);
            String err  = node.path("error").asText(null);
            if (desc != null) return desc;
            if (err  != null) return err;
        } catch (Exception ignored) { /* not JSON — return raw */ }
        return body.length() > 200 ? body.substring(0, 200) + "..." : body;
    }
}
