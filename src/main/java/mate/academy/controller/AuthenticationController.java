package mate.academy.controller;

import java.util.Map;
import java.util.stream.Collectors;
import javax.validation.Valid;
import mate.academy.exception.AuthenticationException;
import mate.academy.model.User;
import mate.academy.model.dto.UserLoginDto;
import mate.academy.model.dto.UserRegistrationDto;
import mate.academy.model.dto.UserResponseDto;
import mate.academy.security.AuthenticationService;
import mate.academy.security.jwt.JwtTokenProvider;
import mate.academy.service.mapper.UserMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserMapper userMapper;

    public AuthenticationController(AuthenticationService authenticationService,
                                    JwtTokenProvider jwtTokenProvider, UserMapper userMapper) {
        this.authenticationService = authenticationService;
        this.jwtTokenProvider = jwtTokenProvider;
        this.userMapper = userMapper;
    }

    @PostMapping("/register")
    public UserResponseDto register(@RequestBody @Valid UserRegistrationDto requestDto) {
        User user = authenticationService.register(requestDto.getEmail(),
                requestDto.getPassword());
        return userMapper.mapToDto(user);
    }

    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody @Valid UserLoginDto userLoginDto)
            throws AuthenticationException {
        User user = authenticationService.login(userLoginDto.getLogin(),
                userLoginDto.getPassword());
        String token = jwtTokenProvider.createToken(user.getEmail(),
                user.getRoles().stream()
                        .map(role -> role.getRoleName().name())
                        .collect(Collectors.toList()));
        return new ResponseEntity<>(Map.of("token", token), HttpStatus.OK);
    }

    @GetMapping
    public String helloPage(Authentication authentication) {
        return String.format("Hello, %s!", authentication.getName());
    }
}
