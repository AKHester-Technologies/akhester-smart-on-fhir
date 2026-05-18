package com.akhester.smartfhir.client.discovery;

/**
 * Thrown when SMART discovery fails — either the network request failed,
 * the ISS returned a non-200 response, or the document is missing
 * required fields (authorization_endpoint, token_endpoint).
 *
 * This is an unchecked exception; callers (SmartLaunchController in Task 3)
 * catch it and return an appropriate HTTP error to the user rather than
 * letting it propagate as a 500.
 */
public class SmartDiscoveryException extends RuntimeException {

    public SmartDiscoveryException(String message) {
        super(message);
    }

    public SmartDiscoveryException(String message, Throwable cause) {
        super(message, cause);
    }
}
