package mate.academy.controller;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.validation.Valid;
import mate.academy.exception.AuthenticationException;
import mate.academy.model.User;
import mate.academy.model.dto.RoleResponseDto;
import mate.academy.model.dto.UserLoginDto;
import mate.academy.model.dto.UserRegistrationDto;
import mate.academy.model.dto.UserResponseDto;
import mate.academy.security.AuthenticationService;
import mate.academy.security.jwt.JwtTokenProvider;
import mate.academy.service.mapper.RoleMapper;
import mate.academy.service.mapper.UserMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    private final RoleMapper roleMapper;
    private final UserMapper userMapper;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthenticationController(AuthenticationService authenticationService,
                                    RoleMapper roleMapper, UserMapper userMapper,
                                    JwtTokenProvider jwtTokenProvider) {
        this.authenticationService = authenticationService;
        this.roleMapper = roleMapper;
        this.userMapper = userMapper;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/register")
    public UserResponseDto register(@RequestBody @Valid UserRegistrationDto userRequestDto) {
        User user = authenticationService.register(userRequestDto.getEmail(),
                userRequestDto.getPassword());
        UserResponseDto userResponseDto = new UserResponseDto();
        userResponseDto.setEmail(user.getEmail());
        List<RoleResponseDto> roles = user.getRoles().stream()
                .map(roleMapper::mapToDto)
                .collect(Collectors.toList());
        userResponseDto.setRoles(roles);
        return userResponseDto;
    }

    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody @Valid UserLoginDto userLoginDto)
            throws AuthenticationException {
        User user = authenticationService.login(
                userLoginDto.getLogin(), userLoginDto.getPassword());
        String token = jwtTokenProvider.createToken(user.getEmail(),
                user.getRoles().stream()
                        . map(role -> role.getRoleName().name())
                        .collect(Collectors.toList()));
        return new ResponseEntity<>(Map.of("token", token), HttpStatus.OK);
    }
}
