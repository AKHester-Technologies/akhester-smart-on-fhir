package com.akhester.smartfhir.client.refresh;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.akhester.smartfhir.client.EpicProperties;
import com.akhester.smartfhir.client.context.SmartContextExtractor;
import com.akhester.smartfhir.client.context.SmartLaunchContext;
import com.akhester.smartfhir.client.token.TokenExchangeException;
import jakarta.servlet.http.HttpSession;
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
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Refreshes an expired (or nearly-expired) access token using the OAuth2
 * {@code refresh_token} grant (RFC 6749 §6).
 *
 * <h3>What it sends</h3>
 * <pre>
 *   POST {token_endpoint}
 *   Content-Type: application/x-www-form-urlencoded
 *
 *   grant_type    = refresh_token
 *   refresh_token = {refresh_token from SmartLaunchContext}
 *   client_id     = {your Epic client ID}
 * </pre>
 *
 * <h3>Epic-specific behaviour</h3>
 * Epic does not always include a {@code refresh_token} in the initial token
 * response — it depends on which scopes were requested and whether the client
 * is registered as a confidential or public client. If {@code refreshToken} is
 * null on the {@link SmartLaunchContext}, this service cannot refresh and
 * returns {@code null} to signal that a full re-launch is required.
 *
 * <h3>Thread safety</h3>
 * A single instance of this service is shared across all requests. The
 * {@link HttpClient} is thread-safe. Concurrent refresh attempts for the same
 * session are possible but harmless — both will succeed and the last write to
 * the session wins (both tokens are valid for the overlap period).
 *
 * <h3>Refresh token rotation</h3>
 * Epic may return a new {@code refresh_token} in the refresh response. If
 * present, it replaces the old one in the updated {@link SmartLaunchContext}.
 * If absent, the original refresh token is retained — Epic allows reuse of
 * refresh tokens within a session.
 */
@Service
public class TokenRefreshService {

    private static final Logger log = LoggerFactory.getLogger(TokenRefreshService.class);

    /**
     * How many seconds before expiry to attempt a proactive refresh.
     * 120s gives enough margin for the network round-trip and any clock skew
     * between the app server and Epic's auth server.
     */
    public static final long REFRESH_BUFFER_SECONDS = 120;

    private final EpicProperties epicProperties;
    private final SmartContextExtractor contextExtractor;
    private final ObjectMapper objectMapper;
    private final HttpClient http;

    public TokenRefreshService(EpicProperties epicProperties,
                                SmartContextExtractor contextExtractor,
                                ObjectMapper objectMapper) {
        this.epicProperties   = epicProperties;
        this.contextExtractor = contextExtractor;
        this.objectMapper     = objectMapper;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    /**
     * Refreshes the access token if it is within {@link #REFRESH_BUFFER_SECONDS}
     * of expiry and a refresh token is available.
     *
     * <h3>Decision tree</h3>
     * <ol>
     *   <li>If the token is not yet near expiry → return {@code existing} unchanged.</li>
     *   <li>If no refresh token → return {@code null} (re-launch required).</li>
     *   <li>POST refresh grant to Epic → update session → return refreshed context.</li>
     * </ol>
     *
     * @param existing       the current launch context
     * @param tokenEndpoint  the token URL from SMART discovery
     * @param session        the current HTTP session — updated if refresh succeeds
     * @return the refreshed {@link SmartLaunchContext}, the original if still valid,
     *         or {@code null} if no refresh token is available
     * @throws TokenRefreshException if the refresh POST fails
     */
    public SmartLaunchContext refreshIfNeeded(SmartLaunchContext existing,
                                              String tokenEndpoint,
                                              HttpSession session) {
        // ── 1. Check if refresh is needed ─────────────────────────────────────
        if (!existing.isTokenExpired(REFRESH_BUFFER_SECONDS)) {
            log.debug("Token still valid for patient={} — no refresh needed", existing.patientId());
            return existing;
        }

        // ── 2. Check refresh token availability ───────────────────────────────
        if (existing.refreshToken() == null || existing.refreshToken().isBlank()) {
            log.warn("Token expired for patient={} but no refresh_token available — re-launch required",
                    existing.patientId());
            return null; // caller must redirect to re-launch
        }

        log.info("Token nearing expiry for patient={} — attempting refresh", existing.patientId());
        return doRefresh(existing, tokenEndpoint, session);
    }

    /**
     * Forces a token refresh regardless of current expiry state.
     * Useful after receiving a 401 from Epic's FHIR API — the token may have
     * been revoked or expired server-side before our local expiry check.
     *
     * Returns {@code null} if no refresh token is available.
     */
    public SmartLaunchContext forceRefresh(SmartLaunchContext existing,
                                           String tokenEndpoint,
                                           HttpSession session) {
        if (existing.refreshToken() == null || existing.refreshToken().isBlank()) {
            log.warn("Force refresh requested for patient={} but no refresh_token — re-launch required",
                    existing.patientId());
            return null;
        }

        log.info("Force refreshing token for patient={}", existing.patientId());
        return doRefresh(existing, tokenEndpoint, session);
    }

    // ── private helpers ───────────────────────────────────────────────────────

    private SmartLaunchContext doRefresh(SmartLaunchContext existing,
                                         String tokenEndpoint,
                                         HttpSession session) {

        // ── Build refresh grant form body ──────────────────────────────────────
        Map<String, String> params = new LinkedHashMap<>();
        params.put("grant_type",    "refresh_token");
        params.put("refresh_token", existing.refreshToken());
        params.put("client_id",     epicProperties.clientId());
        String formBody = buildFormBody(params);

        // ── POST to token endpoint ─────────────────────────────────────────────
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
            throw new TokenRefreshException(
                    "Network error during token refresh for patient=" + existing.patientId(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new TokenRefreshException("Token refresh interrupted", e);
        }

        // ── Handle non-200 ────────────────────────────────────────────────────
        if (response.statusCode() != 200) {
            String detail = extractError(response.body());
            log.error("Token refresh failed HTTP {} for patient={} — {}",
                    response.statusCode(), existing.patientId(), detail);
            throw new TokenRefreshException(
                    "Token refresh failed HTTP %d: %s".formatted(response.statusCode(), detail));
        }

        // ── Parse response ─────────────────────────────────────────────────────
        String newAccessToken;
        String newRefreshToken;
        long   expiresIn;
        try {
            var node = objectMapper.readTree(response.body());
            newAccessToken  = node.path("access_token").asText(null);
            newRefreshToken = node.path("refresh_token").asText(null); // may be absent
            expiresIn       = node.path("expires_in").asLong(3600);
        } catch (IOException e) {
            throw new TokenRefreshException(
                    "Failed to parse token refresh response: " + e.getMessage(), e);
        }

        if (newAccessToken == null || newAccessToken.isBlank()) {
            throw new TokenRefreshException(
                    "Token refresh response missing access_token for patient=" + existing.patientId());
        }

        // ── Compute new expiry ─────────────────────────────────────────────────
        Instant newExpiry = Instant.now().plusSeconds(expiresIn);

        // ── Update context — preserve all non-token fields ─────────────────────
        // If Epic returned a new refresh_token (rotation), update it.
        // If not, keep the existing one — Epic allows refresh token reuse.
        String effectiveRefreshToken = (newRefreshToken != null && !newRefreshToken.isBlank())
                ? newRefreshToken
                : existing.refreshToken();

        // Build the refreshed context directly to capture the potentially
        // rotated refresh token (contextExtractor.refresh() doesn't update refreshToken).
        SmartLaunchContext refreshed = new SmartLaunchContext(
                newAccessToken,
                existing.patientId(),
                existing.encounterId(),
                existing.fhirBaseUrl(),
                existing.needPatientBanner(),
                existing.scope(),
                newExpiry,
                effectiveRefreshToken,
                existing.userProfile()  // user profile does not change on token refresh
        );

        session.setAttribute(SmartLaunchContext.SESSION_KEY, refreshed);

        log.info("Token refreshed for patient={} — newExpiry={}, refreshTokenRotated={}",
                refreshed.patientId(), newExpiry,
                newRefreshToken != null && !newRefreshToken.isBlank());

        return refreshed;
    }

    private String buildFormBody(Map<String, String> params) {
        return params.entrySet().stream()
                .map(e -> encode(e.getKey()) + "=" + encode(e.getValue()))
                .collect(Collectors.joining("&"));
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private String extractError(String body) {
        try {
            var node = objectMapper.readTree(body);
            String desc = node.path("error_description").asText(null);
            String err  = node.path("error").asText(null);
            if (desc != null) return desc;
            if (err  != null) return err;
        } catch (Exception ignored) { /* not JSON */ }
        return body.length() > 200 ? body.substring(0, 200) + "..." : body;
    }
}
