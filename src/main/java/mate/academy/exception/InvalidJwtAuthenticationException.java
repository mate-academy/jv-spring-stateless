package mate.academy.exception;

public class InvalidJwtAuthenticationException extends AuthenticationException{
    public InvalidJwtAuthenticationException(String message) {
        super(message);
    }
}
