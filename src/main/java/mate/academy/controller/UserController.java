package mate.academy.controller;

import java.util.List;
import mate.academy.model.User;
import mate.academy.model.dto.UserRegistrationDto;
import mate.academy.model.dto.UserResponseDto;
import mate.academy.service.UserService;
import mate.academy.service.mapper.UserMapper;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
public class UserController {
    private final UserService userService;
    private final UserMapper userMapper;

    public UserController(UserService userService, UserMapper userMapper) {
        this.userService = userService;
        this.userMapper = userMapper;
    }

    @GetMapping
    public List<UserResponseDto> getAll() {
        return userService.findAll()
                .stream()
                .map(userMapper::mapToDto)
                .toList();
    }

    @GetMapping("/{id}")
    public UserResponseDto get(@PathVariable Long id) {
        return userMapper.mapToDto(userService.findById(id));
    }

    @PostMapping
    public UserResponseDto create(@RequestBody UserRegistrationDto dto) {
        User user = userService.save(userMapper.mapToModel(dto));
        return userMapper.mapToDto(user);
    }

    @DeleteMapping("/{id}")
    public void delete(@PathVariable Long id) {
        userService.delete(id);
    }
}
