package com.akhester.smartfhir.client.oidc;

/**
 * Thrown when the OIDC {@code id_token} fails validation.
 *
 * Specific failure causes:
 * <ul>
 *   <li>JWT signature invalid (wrong key or tampered token)</li>
 *   <li>Token expired ({@code exp} claim in the past)</li>
 *   <li>Wrong audience ({@code aud} ≠ our client ID)</li>
 *   <li>Wrong issuer ({@code iss} ≠ the ISS from the launch)</li>
 *   <li>Missing required claims ({@code sub}, {@code iss}, {@code aud}, {@code exp})</li>
 * </ul>
 *
 * This is an unchecked exception. Callers (SmartContextExtractor) catch it
 * and decide whether to reject the session entirely or proceed without a
 * user profile (allowing FHIR access but no user identity).
 */
public class IdTokenException extends RuntimeException {

    public IdTokenException(String message) {
        super(message);
    }

    public IdTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
