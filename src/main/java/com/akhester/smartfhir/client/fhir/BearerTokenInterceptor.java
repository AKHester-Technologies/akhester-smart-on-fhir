package com.akhester.smartfhir.client.fhir;

import ca.uhn.fhir.rest.client.api.IClientInterceptor;
import ca.uhn.fhir.rest.client.api.IHttpRequest;
import ca.uhn.fhir.rest.client.api.IHttpResponse;

import java.io.IOException;

/**
 * HAPI FHIR client interceptor that attaches a Bearer token to every
 * outbound request made by an {@code IGenericClient}.
 *
 * <h3>Lifecycle</h3>
 * A new interceptor instance is created per session by {@link FhirClientFactory}
 * — one per {@code SmartLaunchContext}. This means the token is captured at
 * client-creation time. If the token is refreshed (Task 9), a new client
 * (and a new interceptor) must be created via {@link FhirClientFactory#create}.
 *
 * <h3>Why not a shared singleton interceptor?</h3>
 * Each authenticated session has its own access token scoped to a specific
 * patient and EHR. Sharing an interceptor across sessions would mix tokens.
 * HAPI's {@code IGenericClient} is cheap to create; we build one per session.
 *
 * <h3>HAPI interceptor contract</h3>
 * {@link #interceptRequest(IHttpRequest)} is called before the HTTP request
 * is sent — the right place to add headers.
 * {@link #interceptResponse(IHttpResponse)} is called after the response is
 * received — we don't need to modify it, so it's a no-op.
 */
public class BearerTokenInterceptor implements IClientInterceptor {

    private final String accessToken;

    public BearerTokenInterceptor(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            throw new IllegalArgumentException("accessToken must not be null or blank");
        }
        this.accessToken = accessToken;
    }

    @Override
    public void interceptRequest(IHttpRequest request) {
        // Adds: Authorization: Bearer eyJ...
        request.addHeader("Authorization", "Bearer " + accessToken);
    }

    @Override
    public void interceptResponse(IHttpResponse response) throws IOException {
        // No-op — we don't modify the response, but we could log it here
        // (see FhirClientFactory.loggingInterceptor for request/response logging)
    }
}
