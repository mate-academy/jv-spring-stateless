package mate.academy.controller;

import java.util.Map;
import javax.validation.Valid;
import mate.academy.exception.AuthenticationException;
import mate.academy.model.User;
import mate.academy.model.dto.UserRegistrationDto;
import mate.academy.model.dto.UserResponseDto;
import mate.academy.security.AuthenticationService;
import mate.academy.security.jwt.JwtTokenProvider;
import mate.academy.service.mapper.UserMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    private final UserMapper userMapper;
    private JwtTokenProvider jwtTokenProvider;

    public AuthenticationController(AuthenticationService authenticationService,
                                    UserMapper userMapper, JwtTokenProvider jwtTokenProvider) {
        this.authenticationService = authenticationService;
        this.userMapper = userMapper;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/register")
    public UserResponseDto register(@RequestBody @Valid UserRegistrationDto userRequestDto) {
        User user = authenticationService.register(userRequestDto.getEmail(),
                userRequestDto.getPassword());
        return userMapper.mapToDto(user);
    }

    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody @Valid UserRegistrationDto userRequestDto)
            throws AuthenticationException {
        User user = authenticationService.login(userRequestDto.getEmail(),
                userRequestDto.getPassword());
        String token = jwtTokenProvider.createToken(user.getEmail(), user.getRoles()
                .stream()
                .toList());
        return new ResponseEntity<>(Map.of("token", token), HttpStatus.OK);
    }
}
