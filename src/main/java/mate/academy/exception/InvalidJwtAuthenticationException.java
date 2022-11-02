package mate.academy.exception;

import org.springframework.http.HttpStatus;

public class InvalidJwtAuthenticationException extends RuntimeException {
    private final HttpStatus httpStatus;

    public InvalidJwtAuthenticationException(String message, HttpStatus httpStatus) {
        this.message = message;
        this.httpStatus = httpStatus;
    }


    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}
