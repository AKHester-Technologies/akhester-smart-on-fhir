package com.akhester.smartfhir.client.discovery;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/**
 * Parsed representation of Epic's SMART discovery document.
 *
 * Fetched at runtime from:
 *   {iss}/.well-known/smart-configuration
 *
 * Epic example (August 2021+ versions):
 * <pre>
 * {
 *   "authorization_endpoint": "https://...oauth2/authorize",
 *   "token_endpoint":         "https://...oauth2/token",
 *   "capabilities": [
 *     "launch-ehr", "client-public", "context-ehr-patient",
 *     "permission-patient", "permission-user", "sso-openid-connect"
 *   ]
 * }
 * </pre>
 *
 * {@code @JsonIgnoreProperties(ignoreUnknown = true)} ensures forward-compatibility
 * if Epic adds new fields — we won't fail to deserialize.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record SmartConfiguration(

        @JsonProperty("authorization_endpoint")
        String authorizationEndpoint,

        @JsonProperty("token_endpoint")
        String tokenEndpoint,

        @JsonProperty("token_endpoint_auth_methods_supported")
        List<String> tokenEndpointAuthMethods,

        @JsonProperty("scopes_supported")
        List<String> scopesSupported,

        @JsonProperty("response_types_supported")
        List<String> responseTypesSupported,

        @JsonProperty("capabilities")
        List<String> capabilities,

        @JsonProperty("code_challenge_methods_supported")
        List<String> codeChallengeMethodsSupported

) {

    /**
     * Returns true if Epic advertises PKCE S256 support in its capabilities.
     * We require this — if absent the ISS is either old or non-Epic.
     */
    public boolean supportsPkceS256() {
        return codeChallengeMethodsSupported != null
                && codeChallengeMethodsSupported.contains("S256");
    }

    /**
     * Returns true if this configuration advertises EHR launch support.
     * Used as a sanity check during Task 3 (launch endpoint).
     */
    public boolean supportsEhrLaunch() {
        return capabilities != null && capabilities.contains("launch-ehr");
    }

    /**
     * Validates that the minimum required fields are present.
     * Called by SmartDiscoveryService after deserialization.
     */
    public void validate(String iss) {
        if (authorizationEndpoint == null || authorizationEndpoint.isBlank()) {
            throw new SmartDiscoveryException(
                    "authorization_endpoint missing in smart-configuration for ISS: " + iss);
        }
        if (tokenEndpoint == null || tokenEndpoint.isBlank()) {
            throw new SmartDiscoveryException(
                    "token_endpoint missing in smart-configuration for ISS: " + iss);
        }
    }
}
