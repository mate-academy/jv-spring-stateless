package mate.academy.controller;

import java.util.List;
import javax.validation.Valid;
import mate.academy.exception.AuthenticationException;
import mate.academy.model.User;
import mate.academy.model.dto.LoginResponseDto;
import mate.academy.model.dto.UserLoginDto;
import mate.academy.model.dto.UserRegistrationDto;
import mate.academy.model.dto.UserResponseDto;
import mate.academy.security.AuthenticationService;
import mate.academy.security.jwt.JwtTokenProvider;
import mate.academy.service.mapper.UserMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    private final UserMapper userMapper;
    private final JwtTokenProvider jwtTokenProvider;

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
    public LoginResponseDto login(@RequestBody UserLoginDto requestDto)
            throws AuthenticationException {
        User user = authenticationService.login(requestDto.getEmail(), requestDto.getPassword());
        List<String> roles = user.getRoles().stream()
                .map(role -> role.getRoleName().name())
                .toList();
        String token = jwtTokenProvider.createToken(user.getEmail(), roles);
        return new LoginResponseDto(token);
    }
}
