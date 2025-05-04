package mate.academy.security;

import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import mate.academy.exception.AuthenticationException;
import mate.academy.model.User;
import mate.academy.security.jwt.JwtTokenProvider;
import mate.academy.service.RoleService;
import mate.academy.service.UserService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {
    private final UserService userService;
    private final RoleService roleService;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthenticationServiceImpl(UserService userService,
                                     RoleService roleService,
                                     PasswordEncoder passwordEncoder,
                                     JwtTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.roleService = roleService;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public User register(String email, String password) {
        User user = new User();
        user.setEmail(email);
        user.setPassword(password);
        user.setRoles(Set.of(roleService.getRoleByName("USER")));
        user = userService.save(user);
        return user;
    }

    @Override
    public User login(String login, String password) throws AuthenticationException {
        Optional<User> user = userService.findByEmail(login);
        if (user.isEmpty() || !passwordEncoder.matches(password, user.get().getPassword())) {
            throw new AuthenticationException("Incorrect username or password!!!");
        }
        return user.get();
    }

    @Override
    public String getToken(User user) {
        return jwtTokenProvider.createToken(user.getEmail(),
                user.getRoles()
                        .stream()
                        .map(role -> role.getRoleName().name())
                        .collect(Collectors.toList()));
    }
}
