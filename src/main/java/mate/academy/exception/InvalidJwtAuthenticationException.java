package mate.academy.exception;

public class InvalidJwtAuthenticationException extends RuntimeException {
    public InvalidJwtAuthenticationException(String massage, Throwable cause) {
        super(massage, cause);
    }
}
