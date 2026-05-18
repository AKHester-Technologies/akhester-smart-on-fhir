package com.akhester.smartfhir.client.fhir;

import ca.uhn.fhir.rest.client.api.IGenericClient;
import ca.uhn.fhir.rest.client.api.IRestfulClientFactory;
import ca.uhn.fhir.rest.client.impl.GenericClient;
import ca.uhn.fhir.rest.client.interceptor.LoggingInterceptor;
import com.akhester.smartfhir.client.context.SmartLaunchContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for FhirClientFactory.
 *
 * Test cases:
 *  1.  create() returns a non-null IGenericClient.
 *  2.  Shared FhirContext is R4.
 *  3.  ServerValidationMode is NEVER (no /metadata fetch on startup).
 *  4.  Two create() calls with different contexts return different clients.
 *  5.  fhirContext() static accessor returns the shared context.
 *  6.  BearerTokenInterceptor is registered on every created client.
 *  7.  LoggingInterceptor is absent when logRequestsAndResponses=false.
 *  8.  LoggingInterceptor is present when logRequestsAndResponses=true.
 *  9.  Null context throws IllegalArgumentException.
 *  10. Expired context still creates a client (expiry is caller's responsibility).
 */
class FhirClientFactoryTest {

    private FhirClientFactory factory;
    private FhirClientFactory loggingFactory;

    private static final String FHIR_BASE = "https://fhir.epic.com/interconnect/api/FHIR/R4";
    private static final String TOKEN_A   = "eyJ.tokenA.sig";
    private static final String TOKEN_B   = "eyJ.tokenB.sig";

    @BeforeEach
    void setUp() {
        factory        = new FhirClientFactory(false, 30000, 10000);
        loggingFactory = new FhirClientFactory(true,  30000, 10000);
    }

    private SmartLaunchContext context(String token) {
        return new SmartLaunchContext(
                token, "ePatient-ABC", "eEncounter-XYZ", FHIR_BASE,
                true, "launch openid patient/Patient.rs",
                Instant.now().plusSeconds(3600), "refresh_token"
        );
    }

    /** Extracts registered interceptors from a HAPI GenericClient. */
    private List<Object> interceptors(IGenericClient client) {
        return ((GenericClient) client)
                .getInterceptorService()
                .getAllRegisteredInterceptors();
    }

    @Test
    void create_returnsNonNullClient() {
        assertThat(factory.create(context(TOKEN_A))).isNotNull();
    }

    @Test
    void fhirContext_isR4() {
        assertThat(FhirClientFactory.fhirContext().getVersion().getVersion().name())
                .isEqualTo("R4");
    }

    @Test
    void fhirContext_serverValidationIsNever() {
        IRestfulClientFactory clientFactory =
                FhirClientFactory.fhirContext().getRestfulClientFactory();
        assertThat(clientFactory.getServerValidationMode().name())
                .isEqualTo("NEVER");
    }

    @Test
    void create_differentContextsReturnDifferentClients() {
        IGenericClient clientA = factory.create(context(TOKEN_A));
        IGenericClient clientB = factory.create(context(TOKEN_B));
        assertThat(clientA).isNotSameAs(clientB);
    }

    @Test
    void fhirContext_staticAccessorReturnsSameInstance() {
        assertThat(FhirClientFactory.fhirContext())
                .isSameAs(FhirClientFactory.fhirContext());
    }

    @Test
    void create_registersBearerTokenInterceptor() {
        // The most important correctness test in this suite:
        // if BearerTokenInterceptor is not registered, every FHIR call goes
        // unauthenticated and Epic silently returns 401.
        IGenericClient client = factory.create(context(TOKEN_A));
        boolean hasBearerInterceptor = interceptors(client).stream()
                .anyMatch(i -> i instanceof BearerTokenInterceptor);
        assertThat(hasBearerInterceptor)
                .as("BearerTokenInterceptor must be registered on every client")
                .isTrue();
    }

    @Test
    void create_withLoggingFalse_doesNotRegisterLoggingInterceptor() {
        IGenericClient client = factory.create(context(TOKEN_A));
        boolean hasLogging = interceptors(client).stream()
                .anyMatch(i -> i instanceof LoggingInterceptor);
        assertThat(hasLogging)
                .as("LoggingInterceptor must NOT be present when logging=false")
                .isFalse();
    }

    @Test
    void create_withLoggingTrue_registersLoggingInterceptor() {
        IGenericClient client = loggingFactory.create(context(TOKEN_A));
        boolean hasLogging = interceptors(client).stream()
                .anyMatch(i -> i instanceof LoggingInterceptor);
        assertThat(hasLogging)
                .as("LoggingInterceptor must be present when logging=true")
                .isTrue();
    }

    @Test
    void create_withNullContext_throwsIllegalArgumentException() {
        assertThatThrownBy(() -> factory.create(null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("null");
    }

    @Test
    void create_withExpiredContext_stillCreatesClient() {
        // Expiry checking is the caller's responsibility (PatientDataController.requireContext)
        SmartLaunchContext expiredCtx = new SmartLaunchContext(
                TOKEN_A, "ePatient-ABC", null, FHIR_BASE,
                false, "launch", Instant.now().minusSeconds(60), null
        );
        assertThatNoException().isThrownBy(() -> factory.create(expiredCtx));
    }
}
