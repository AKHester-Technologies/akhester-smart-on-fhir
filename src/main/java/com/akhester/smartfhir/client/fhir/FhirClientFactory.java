package com.akhester.smartfhir.client.fhir;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.client.api.IGenericClient;
import ca.uhn.fhir.rest.client.api.ServerValidationModeEnum;
import ca.uhn.fhir.rest.client.interceptor.LoggingInterceptor;
import com.akhester.smartfhir.client.context.SmartLaunchContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Creates HAPI FHIR R4 {@link IGenericClient} instances scoped to a
 * {@link SmartLaunchContext}.
 *
 * <h3>One client per session</h3>
 * Each authenticated session gets its own {@code IGenericClient} configured
 * with that session's access token and FHIR base URL (ISS). The factory
 * is a singleton Spring bean; the clients it creates are not — they are
 * created on demand and typically stored in the HTTP session or passed
 * directly to service methods.
 *
 * <h3>Why a shared FhirContext?</h3>
 * {@link FhirContext} is expensive to create (it scans the classpath for FHIR
 * model classes). It is thread-safe and designed to be shared. We create one
 * {@code FhirContext.forR4()} at factory construction and reuse it across all
 * client instances — the standard HAPI recommendation.
 *
 * <h3>ServerValidationModeEnum.NEVER</h3>
 * By default HAPI fetches the server's {@code /metadata} (CapabilityStatement)
 * on first use to validate it supports the requested operations. Epic's sandbox
 * returns a valid metadata document, but fetching it adds 300–500ms of latency
 * on first use. We disable it — our clients are always pointed at known Epic
 * FHIR servers that we've already verified via SMART discovery.
 *
 * <h3>Token refresh</h3>
 * When Task 9 refreshes the access token, call {@link #create(SmartLaunchContext)}
 * again with the updated context to get a new client with the new token.
 */
@Component
public class FhirClientFactory {

    private static final Logger log = LoggerFactory.getLogger(FhirClientFactory.class);

    /**
     * Shared R4 context — thread-safe, expensive to create, reused across all clients.
     * Declared static so it survives for the application lifetime without
     * requiring Spring to manage its lifecycle separately.
     */
    private static final FhirContext FHIR_CONTEXT;

    static {
        // No logging here — SLF4J may not yet be initialised when this class
        // is first loaded in custom test configurations. Log in the constructor instead.
        FHIR_CONTEXT = FhirContext.forR4();
        // Disable server capability validation — see class Javadoc
        FHIR_CONTEXT.getRestfulClientFactory()
                .setServerValidationMode(ServerValidationModeEnum.NEVER);
    }

    private final boolean logRequestsAndResponses;

    /**
     * @param logRequestsAndResponses  controlled by {@code hapi.fhir.log-requests-and-responses}
     * @param socketTimeoutMs          controlled by {@code hapi.fhir.socket-timeout-ms}
     * @param connectTimeoutMs         controlled by {@code hapi.fhir.connect-timeout-ms}
     */
    public FhirClientFactory(
            @Value("${hapi.fhir.log-requests-and-responses:false}")
            boolean logRequestsAndResponses,
            @Value("${hapi.fhir.socket-timeout-ms:30000}")
            int socketTimeoutMs,
            @Value("${hapi.fhir.connect-timeout-ms:10000}")
            int connectTimeoutMs) {
        this.logRequestsAndResponses = logRequestsAndResponses;
        // Wire application.yml timeouts into the shared HAPI client factory.
        FHIR_CONTEXT.getRestfulClientFactory().setSocketTimeout(socketTimeoutMs);
        FHIR_CONTEXT.getRestfulClientFactory().setConnectTimeout(connectTimeoutMs);
        log.info("FhirClientFactory ready — socketTimeout={}ms, connectTimeout={}ms",
                socketTimeoutMs, connectTimeoutMs);
    }

    /**
     * Creates a fully configured HAPI R4 client for the given launch context.
     *
     * The returned client is pre-configured with:
     * <ul>
     *   <li>FHIR base URL = {@code context.fhirBaseUrl()}</li>
     *   <li>Bearer token from {@code context.accessToken()}</li>
     *   <li>10s socket + connect timeouts (from application.yml)</li>
     *   <li>Optional request/response logging (dev only)</li>
     * </ul>
     *
     * @param context the authenticated launch context from Task 6
     * @return a ready-to-use {@link IGenericClient}
     */
    public IGenericClient create(SmartLaunchContext context) {
        if (context == null) {
            throw new IllegalArgumentException("SmartLaunchContext must not be null");
        }
        log.debug("Creating FHIR client — baseUrl={}, patient={}",
                context.fhirBaseUrl(), context.patientId());

        IGenericClient client = FHIR_CONTEXT.newRestfulGenericClient(context.fhirBaseUrl());

        // ── Bearer token ──────────────────────────────────────────────────────
        client.registerInterceptor(new BearerTokenInterceptor(context.accessToken()));

        // ── Request/response logging (dev only) ───────────────────────────────
        if (logRequestsAndResponses) {
            LoggingInterceptor loggingInterceptor = new LoggingInterceptor();
            loggingInterceptor.setLogRequestSummary(true);
            loggingInterceptor.setLogResponseSummary(true);
            loggingInterceptor.setLogRequestBody(false);   // avoid logging PHI in dev
            loggingInterceptor.setLogResponseBody(false);
            client.registerInterceptor(loggingInterceptor);
        }

        return client;
    }

    /**
     * Returns the shared {@link FhirContext} — useful for parsers, validators,
     * or other HAPI utilities that need a context but not a full client.
     */
    public static FhirContext fhirContext() {
        return FHIR_CONTEXT;
    }
}
