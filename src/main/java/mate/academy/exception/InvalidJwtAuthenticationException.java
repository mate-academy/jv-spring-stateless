package mate.academy.exception;

public class InvalidJwtAuthenticationException extends RuntimeException {
    public InvalidJwtAuthenticationException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
