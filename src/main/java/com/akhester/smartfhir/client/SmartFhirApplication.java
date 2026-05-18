package com.akhester.smartfhir.client;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Entry point for the SMART on FHIR Epic EHR launch client.
 *
 * Launch flow overview (each step = one Task):
 *
 *  1. Epic calls   GET /launch?iss=...&launch=...       → SmartLaunchController  (Task 3)
 *  2. App fetches  {iss}/.well-known/smart-configuration → SmartDiscoveryService  (Task 2)
 *  3. App builds   authorize URL + PKCE + Epic params    → SmartAuthRequestBuilder (Task 4)
 *  4. Epic calls   GET /callback?code=...&state=...     → SmartCallbackController (Task 5)
 *  5. App POSTs    token endpoint (code + verifier)     → SmartTokenService       (Task 5)
 *  6. App extracts patient, encounter from token extras → SmartContextExtractor   (Task 6)
 *  7. App creates  HAPI IGenericClient + bearer token   → FhirClientFactory       (Task 7)
 */
@SpringBootApplication
@ConfigurationPropertiesScan   // picks up @ConfigurationProperties beans (Task 2+)
public class SmartFhirApplication {

    public static void main(String[] args) {
        SpringApplication.run(SmartFhirApplication.class, args);
    }
}
