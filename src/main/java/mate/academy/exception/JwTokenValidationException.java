package mate.academy.exception;

public class JwTokenValidationException extends RuntimeException {
    public JwTokenValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
