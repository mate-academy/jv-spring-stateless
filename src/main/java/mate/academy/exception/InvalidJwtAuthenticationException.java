package mate.academy.exception;

public class InvalidJwtAuthenticationException extends RuntimeException {
    InvalidJwtAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
