package mate.academy.exception;

public class InvalidJwtAuthenticationException extends RuntimeException{
    public InvalidJwtAuthenticationException(String message, Exception e) {
        super(message, e);
    }
}
