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
import mate.academy.security.JwtTokenProvider;
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
    private final UserMapper userMapper;
    private final RoleMapper roleMapper;
    private final JwtTokenProvider provider;

    public AuthenticationController(AuthenticationService authenticationService,
                                    UserMapper userMapper, RoleMapper roleMapper,
                                    JwtTokenProvider provider) {
        this.authenticationService = authenticationService;
        this.userMapper = userMapper;
        this.roleMapper = roleMapper;
        this.provider = provider;
    }

    @PostMapping("/register")
    public UserResponseDto register(@RequestBody @Valid UserRegistrationDto userRequestDto) {
        User user = authenticationService.register(userRequestDto.getEmail(),
                userRequestDto.getPassword());
        String token = provider.createToken(user.getEmail(), user.getRoles().stream()
                .map(r -> r.getRoleName().name())
                .collect(Collectors.toList()));
        UserResponseDto responseDto = new UserResponseDto();
        responseDto.setEmail(user.getEmail());
        responseDto.setRoles(user.getRoles().stream()
                .map(roleMapper::mapToDto).collect(Collectors.toList()));
        return responseDto;
    }

    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody @Valid UserLoginDto userDto)
            throws AuthenticationException {
        User user = authenticationService.login(userDto.getLogin(), userDto.getPassword());
        String token = provider.createToken(user.getEmail(), user.getRoles().stream()
                .map(r -> r.getRoleName().name())
                .collect(Collectors.toList()));
        return new ResponseEntity<>(Map.of("token", token), HttpStatus.OK);
    }
}
