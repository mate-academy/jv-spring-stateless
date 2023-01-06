package mate.academy.exception;

public class InvalidJwtAuthenticationException extends Exception {
    public InvalidJwtAuthenticationException(String message) {
        super(message);
    }
}