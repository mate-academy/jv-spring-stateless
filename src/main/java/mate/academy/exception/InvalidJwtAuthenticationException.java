package mate.academy.exception;

public class InvalidJwtAuthenticationException extends RuntimeException {
    public InvalidJwtAuthenticationException(String exceptionMessage, RuntimeException e) {
        super(exceptionMessage, e);
    }
}
