package com.akhester.smartfhir.client.token;

/**
 * Thrown when the token exchange POST to Epic's token endpoint fails —
 * either a network error, a non-200 HTTP response, malformed JSON,
 * or a missing required field in the response.
 *
 * Caught by {@link SmartCallbackController} and converted to an appropriate
 * HTTP error response rather than a 500.
 */
public class TokenExchangeException extends RuntimeException {

    public TokenExchangeException(String message) {
        super(message);
    }

    public TokenExchangeException(String message, Throwable cause) {
        super(message, cause);
    }
}
