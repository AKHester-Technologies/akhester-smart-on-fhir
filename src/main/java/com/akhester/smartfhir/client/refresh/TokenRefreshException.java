package com.akhester.smartfhir.client.refresh;

/**
 * Thrown when the OAuth2 {@code refresh_token} grant fails — either a network
 * error, a non-200 HTTP response from Epic's token endpoint, or a malformed
 * response body.
 *
 * Distinguishable from {@link com.akhester.smartfhir.client.token.TokenExchangeException}
 * (which covers the initial authorization_code grant) so callers can handle
 * each failure mode differently:
 * - {@code TokenExchangeException} → re-launch required (the code is unusable)
 * - {@code TokenRefreshException}  → may retry once, then re-launch
 */
public class TokenRefreshException extends RuntimeException {

    public TokenRefreshException(String message) {
        super(message);
    }

    public TokenRefreshException(String message, Throwable cause) {
        super(message, cause);
    }
}
