package com.akhester.smartfhir.client.discovery;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.akhester.smartfhir.client.EpicProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Fetches and caches the SMART discovery document from an Epic ISS URL.
 *
 * <h3>What it does</h3>
 * Given an ISS like {@code https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4},
 * it GETs {@code {iss}/.well-known/smart-configuration} and returns a parsed
 * {@link SmartConfiguration} with the authorization and token endpoint URLs.
 *
 * <h3>Caching</h3>
 * Results are cached in-memory per ISS for {@code smart.epic.discovery-cache-minutes}
 * (default 60 min). Epic's config rarely changes — re-fetching on every launch
 * would add ~100–300ms of latency for no benefit.
 *
 * A hospital can have its own ISS (not just the Epic sandbox), so the cache
 * is keyed by ISS string — not a single global entry.
 *
 * <h3>Why java.net.http.HttpClient, not RestTemplate/WebClient?</h3>
 * Discovery is a single synchronous blocking call made once per ISS.
 * The built-in Java 11+ HttpClient avoids pulling in extra dependencies
 * for this one use case. Tasks 5+ (token exchange, FHIR calls) use
 * Spring's OAuth2 client and HAPI respectively.
 */
@Service
public class SmartDiscoveryService {

    private static final Logger log = LoggerFactory.getLogger(SmartDiscoveryService.class);

    private static final String WELL_KNOWN_PATH = "/.well-known/smart-configuration";

    private final HttpClient http;
    private final ObjectMapper objectMapper;
    private final Duration cacheTtl;

    /** Cache entry — wraps the config with the time it was fetched. */
    private record CacheEntry(SmartConfiguration config, Instant fetchedAt) {}

    private final Map<String, CacheEntry> cache = new ConcurrentHashMap<>();

    public SmartDiscoveryService(EpicProperties epicProperties, ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.cacheTtl = Duration.ofMinutes(epicProperties.discoveryCacheMinutes());
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .followRedirects(HttpClient.Redirect.NORMAL)
                .build();
    }

    /**
     * Returns the SMART configuration for the given ISS.
     *
     * Hits the network only when the cache is empty or stale.
     *
     * @param iss the FHIR base URL passed by Epic in the launch request
     * @return parsed and validated {@link SmartConfiguration}
     * @throws SmartDiscoveryException if the network call fails or the document
     *                                  is missing required fields
     * @throws IllegalArgumentException if the ISS is null or blank
     */
    public SmartConfiguration discover(String iss) {
        if (iss == null || iss.isBlank()) {
            throw new IllegalArgumentException("ISS must not be null or blank");
        }

        // Normalize: strip trailing slash so URL construction is predictable.
        String normalizedIss = iss.stripTrailing().replaceAll("/+$", "");

        // Check cache first (non-atomic read, avoids unnecessary locking on hot path).
        CacheEntry cached = cache.get(normalizedIss);
        if (cached != null && !isExpired(cached)) {
            log.debug("SMART discovery cache hit for ISS: {}", normalizedIss);
            return cached.config();
        }

        // Cache miss or stale — fetch. computeIfAbsent on ConcurrentHashMap is atomic
        // per key, preventing the thundering-herd double-fetch under burst load.
        // We evict stale entries first so computeIfAbsent always runs for expired keys.
        if (cached != null && isExpired(cached)) {
            cache.remove(normalizedIss, cached); // only remove if still the same entry
        }

        CacheEntry fresh = cache.computeIfAbsent(normalizedIss, key -> {
            log.info("Fetching SMART configuration from ISS: {}", key);
            SmartConfiguration config = fetchAndParse(key);
            config.validate(key);
            log.info("SMART configuration cached — authEndpoint={}, tokenEndpoint={}",
                    config.authorizationEndpoint(), config.tokenEndpoint());
            return new CacheEntry(config, Instant.now());
        });

        return fresh.config();
    }

    /**
     * Removes the cached entry for the given ISS, forcing a fresh fetch
     * on the next {@link #discover(String)} call.
     *
     * Useful in tests and if Epic rotates its endpoints.
     */
    public void evict(String iss) {
        cache.remove(iss.stripTrailing().replaceAll("/+$", ""));
    }

    /**
     * Package-private for testing only — injects a pre-populated cache entry.
     * Do NOT call from production code; use {@link #discover(String)} instead.
     *
     * @VisibleForTesting
     */
    void putCacheEntry(String iss, SmartConfiguration config) {
        cache.put(iss, new CacheEntry(config, Instant.now()));
    }

    // ── private helpers ───────────────────────────────────────────────────────

    private SmartConfiguration fetchAndParse(String normalizedIss) {
        URI discoveryUri = UriComponentsBuilder
                .fromUriString(normalizedIss)
                .path(WELL_KNOWN_PATH)
                .build()
                .toUri();

        HttpRequest request = HttpRequest.newBuilder(discoveryUri)
                .GET()
                .header("Accept", "application/json")
                .timeout(Duration.ofSeconds(15))
                .build();

        HttpResponse<String> response;
        try {
            response = http.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new SmartDiscoveryException(
                    "Network error fetching SMART configuration from: " + discoveryUri, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SmartDiscoveryException(
                    "Interrupted while fetching SMART configuration from: " + discoveryUri, e);
        }

        if (response.statusCode() != 200) {
            throw new SmartDiscoveryException(
                    "SMART configuration endpoint returned HTTP %d for ISS: %s"
                            .formatted(response.statusCode(), normalizedIss));
        }

        try {
            return objectMapper.readValue(response.body(), SmartConfiguration.class);
        } catch (IOException e) {
            throw new SmartDiscoveryException(
                    "Failed to parse SMART configuration JSON from ISS: " + normalizedIss, e);
        }
    }

    private boolean isExpired(CacheEntry entry) {
        return Instant.now().isAfter(entry.fetchedAt().plus(cacheTtl));
    }
}
