package mate.academy.exception;

public class InvalidJwtAuthenticationException extends RuntimeException {
    public InvalidJwtAuthenticationException(String message, RuntimeException cause) {
        super(message, cause);
    }
}
