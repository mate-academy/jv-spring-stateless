package mate.academy.exception;

import io.jsonwebtoken.JwtException;

public class InvalidJwtAuthenticationException extends JwtException {
    public InvalidJwtAuthenticationException(String message, RuntimeException e) {
        super(message, e);
    }
}
