package com.autoauth.exception;

/**
 * An access JWT whose signature and remaining claim contract are valid, but whose
 * expiration is outside the clock tolerance. It must never authenticate a request.
 */
public class ExpiredAccessTokenException extends JwtValidationException {
    /** @param cause the verified parser expiration failure */
    public ExpiredAccessTokenException(Throwable cause) {
        super("Access token expired", cause);
    }
}
