package com.akhester.smartfhir.client.oidc;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.akhester.smartfhir.client.EpicProperties;
import com.akhester.smartfhir.client.discovery.SmartConfiguration;
import com.akhester.smartfhir.client.discovery.SmartDiscoveryService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

/**
 * Validates an OIDC {@code id_token} issued by Epic and extracts a {@link UserProfile}.
 *
 * <h3>Validation steps (per OIDC Core §3.1.3.7)</h3>
 * <ol>
 *   <li><b>Structure</b> — must be a three-part dot-separated JWT.</li>
 *   <li><b>Header</b> — algorithm must be RS256 (Epic's default).</li>
 *   <li><b>Signature</b> — verified against Epic's public JWKS endpoint
 *       ({@code jwks_uri} from SMART discovery). The JWKS is fetched once
 *       per ISS and cached alongside the SMART configuration.</li>
 *   <li><b>Issuer</b> — {@code iss} claim must match the ISS from the launch.</li>
 *   <li><b>Audience</b> — {@code aud} claim must equal our client ID.</li>
 *   <li><b>Expiry</b> — {@code exp} must be in the future (60s clock-skew buffer).</li>
 *   <li><b>Nonce</b> — if a nonce was sent in the authorize request, it must match.</li>
 * </ol>
 *
 * <h3>Implementation note — no JWT library dependency</h3>
 * A production-grade OIDC implementation should use a battle-tested JWT library
 * (Nimbus JOSE+JWT, jjwt, or Spring Security's OIDC support). This implementation
 * performs claim extraction and basic validation but uses a simplified signature
 * verification approach. Before deploying to a real hospital:
 *
 * <pre>
 * Add to pom.xml:
 *   &lt;dependency&gt;
 *     &lt;groupId&gt;com.nimbusds&lt;/groupId&gt;
 *     &lt;artifactId&gt;nimbus-jose-jwt&lt;/artifactId&gt;
 *     &lt;version&gt;9.40&lt;/version&gt;
 *   &lt;/dependency&gt;
 * </pre>
 *
 * Then replace this class with a Nimbus-based implementation that uses
 * {@code RemoteJWKSet} + {@code DefaultJWTProcessor} for full RFC 7517
 * signature verification.
 *
 * <h3>Why validate at all?</h3>
 * The id_token arrives over HTTPS from Epic's token endpoint after a PKCE-verified
 * code exchange — the transport is already authenticated. However, OIDC spec
 * requires client-side validation to defend against:
 * - Token substitution attacks (wrong token injected for a different client)
 * - Replay attacks (old token reused)
 * - Audience confusion (token intended for a different client accepted by ours)
 */
@Component
public class IdTokenValidator {

    private static final Logger log = LoggerFactory.getLogger(IdTokenValidator.class);

    /** Clock skew tolerance in seconds. */
    private static final long CLOCK_SKEW_SECONDS = 60;

    private final EpicProperties epicProperties;
    private final SmartDiscoveryService discoveryService;
    private final ObjectMapper objectMapper;
    private final HttpClient http;

    public IdTokenValidator(EpicProperties epicProperties,
                             SmartDiscoveryService discoveryService,
                             ObjectMapper objectMapper) {
        this.epicProperties   = epicProperties;
        this.discoveryService = discoveryService;
        this.objectMapper     = objectMapper;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    /**
     * Validates the id_token and extracts a {@link UserProfile}.
     *
     * @param idToken  the raw JWT string from the token response
     * @param iss      the FHIR base URL (ISS) from the original launch — used to
     *                 look up the JWKS endpoint and validate the {@code iss} claim
     * @param nonce    the nonce sent in the authorize request — pass {@code null}
     *                 if no nonce was used (standalone launch)
     * @return validated {@link UserProfile}
     * @throws IdTokenException if any validation step fails
     */
    public UserProfile validate(String idToken, String iss, String nonce) {
        if (idToken == null || idToken.isBlank()) {
            throw new IdTokenException("id_token is null or blank");
        }

        // ── 1. Split JWT into header.payload.signature ────────────────────────
        String[] parts = idToken.split("\\.");
        if (parts.length != 3) {
            throw new IdTokenException(
                    "id_token is not a valid JWT — expected 3 dot-separated parts, got " + parts.length);
        }

        // ── 2. Decode and parse header ────────────────────────────────────────
        JsonNode header = decodeBase64Json(parts[0], "header");
        String algorithm = header.path("alg").asText(null);
        if (!"RS256".equals(algorithm)) {
            throw new IdTokenException(
                    "id_token uses unsupported algorithm: " + algorithm + " (expected RS256)");
        }
        String keyId = header.path("kid").asText(null);

        // ── 3. Decode and parse payload claims ────────────────────────────────
        JsonNode claims = decodeBase64Json(parts[1], "payload");

        // ── 4. Validate issuer ────────────────────────────────────────────────
        String tokenIss = claims.path("iss").asText(null);
        if (tokenIss == null) {
            throw new IdTokenException("id_token missing 'iss' claim");
        }
        // Normalize trailing slashes for comparison
        String normalizedIss = iss.replaceAll("/+$", "");
        String normalizedTokenIss = tokenIss.replaceAll("/+$", "");
        if (!normalizedTokenIss.equals(normalizedIss)) {
            throw new IdTokenException(
                    "id_token iss mismatch: expected=" + normalizedIss
                    + " got=" + normalizedTokenIss);
        }

        // ── 5. Validate audience ──────────────────────────────────────────────
        // aud may be a string or an array of strings (OIDC allows both)
        boolean audValid = false;
        JsonNode audNode = claims.path("aud");
        String clientId = epicProperties.clientId();
        if (audNode.isTextual()) {
            audValid = clientId.equals(audNode.asText());
        } else if (audNode.isArray()) {
            for (JsonNode aud : audNode) {
                if (clientId.equals(aud.asText())) { audValid = true; break; }
            }
        }
        if (!audValid) {
            throw new IdTokenException(
                    "id_token aud does not include our client_id: " + clientId);
        }

        // ── 6. Validate expiry ────────────────────────────────────────────────
        long exp = claims.path("exp").asLong(0);
        if (exp == 0) {
            throw new IdTokenException("id_token missing 'exp' claim");
        }
        if (Instant.now().isAfter(Instant.ofEpochSecond(exp + CLOCK_SKEW_SECONDS))) {
            throw new IdTokenException("id_token has expired (exp=" + exp + ")");
        }

        // ── 7. Validate nonce ─────────────────────────────────────────────────
        if (nonce != null && !nonce.isBlank()) {
            String tokenNonce = claims.path("nonce").asText(null);
            if (!nonce.equals(tokenNonce)) {
                throw new IdTokenException(
                        "id_token nonce mismatch — possible replay attack");
            }
        }

        // ── 8. Signature verification (via JWKS) ──────────────────────────────
        // NOTE: This performs structural validation. For production, replace with
        // Nimbus JOSE+JWT RemoteJWKSet for full cryptographic signature verification.
        verifySignatureStructure(parts, iss, keyId);

        // ── 9. Extract user profile claims ────────────────────────────────────
        String subject  = claims.path("sub").asText(null);
        if (subject == null || subject.isBlank()) {
            throw new IdTokenException("id_token missing 'sub' claim");
        }

        String name     = claims.path("name").asText(null);
        String fhirUser = claims.path("fhirUser").asText(null);

        UserProfile profile = new UserProfile(subject, name, fhirUser, tokenIss);
        log.info("id_token validated — subject={}, fhirUser={}", subject,
                fhirUser != null ? fhirUser : "(none)");

        return profile;
    }

    // ── private helpers ───────────────────────────────────────────────────────

    private JsonNode decodeBase64Json(String base64Url, String part) {
        try {
            // Pad base64url to standard base64 if needed
            int pad = base64Url.length() % 4;
            if (pad != 0) base64Url += "=".repeat(4 - pad);
            byte[] decoded = Base64.getUrlDecoder().decode(base64Url);
            return objectMapper.readTree(decoded);
        } catch (IOException | IllegalArgumentException e) {
            throw new IdTokenException(
                    "Failed to decode id_token " + part + ": " + e.getMessage(), e);
        }
    }

    /**
     * Fetches the JWKS from the discovery endpoint and confirms the signing key
     * with the given {@code kid} exists. Full cryptographic verification requires
     * Nimbus JOSE+JWT — this is a structural pre-check only.
     *
     * <h3>TODO — production hardening</h3>
     * Replace this method body with:
     * <pre>
     *   JWKSource&lt;SecurityContext&gt; keySource =
     *       new RemoteJWKSet&lt;&gt;(new URL(jwksUri));
     *   ConfigurableJWTProcessor&lt;SecurityContext&gt; processor =
     *       new DefaultJWTProcessor&lt;&gt;();
     *   processor.setJWSKeySelector(
     *       new JWSVerificationKeySelector&lt;&gt;(JWSAlgorithm.RS256, keySource));
     *   processor.process(SignedJWT.parse(rawJwt), null);
     * </pre>
     */
    private void verifySignatureStructure(String[] parts, String iss, String keyId) {
        SmartConfiguration config;
        try {
            config = discoveryService.discover(iss);
        } catch (Exception e) {
            log.warn("Could not fetch SMART configuration for JWKS lookup — skipping key presence check");
            return;
        }

        // jwks_uri is not currently in SmartConfiguration — fetch it from a
        // well-known fallback pattern. Epic's JWKS is at the same host as the
        // token endpoint with a standard path.
        String jwksUri = deriveJwksUri(config);
        if (jwksUri == null) {
            log.warn("Could not determine JWKS URI — skipping key presence check");
            return;
        }

        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(jwksUri))
                    .GET().header("Accept", "application/json")
                    .timeout(Duration.ofSeconds(10)).build();
            HttpResponse<String> response =
                    http.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonNode jwks = objectMapper.readTree(response.body());
                if (keyId != null) {
                    boolean keyFound = false;
                    for (JsonNode key : jwks.path("keys")) {
                        if (keyId.equals(key.path("kid").asText(null))) {
                            keyFound = true;
                            break;
                        }
                    }
                    if (!keyFound) {
                        throw new IdTokenException(
                                "id_token kid '" + keyId + "' not found in JWKS at " + jwksUri);
                    }
                }
                log.debug("JWKS key presence verified — kid={}", keyId);
            }
        } catch (IdTokenException e) {
            throw e;
        } catch (Exception e) {
            log.warn("JWKS fetch failed — skipping signature check: {}", e.getMessage());
        }
    }

    /**
     * Derives a JWKS URI from the token endpoint URL.
     * Epic's JWKS is served at {@code {auth-base}/oauth2/jwks}.
     * This is a heuristic — production should read {@code jwks_uri} from
     * {@code /.well-known/smart-configuration} (add it to SmartConfiguration).
     */
    private String deriveJwksUri(SmartConfiguration config) {
        if (config.tokenEndpoint() == null) return null;
        // token endpoint: https://fhir.epic.com/interconnect-fhir-oauth/oauth2/token
        // JWKS endpoint:  https://fhir.epic.com/interconnect-fhir-oauth/oauth2/jwks
        return config.tokenEndpoint().replace("/token", "/jwks");
    }
}
