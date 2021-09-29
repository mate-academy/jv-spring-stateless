package mate.academy.security;

import mate.academy.exception.InvalidJwtAuthenticationException;
import mate.academy.model.User;

public interface AuthenticationService {
    User register(String email, String password);

    User login(String login, String password) throws InvalidJwtAuthenticationException;
}
