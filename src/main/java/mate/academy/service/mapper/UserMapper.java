package mate.academy.service.mapper;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import mate.academy.model.User;
import mate.academy.model.dto.RoleResponseDto;
import mate.academy.model.dto.UserRegistrationDto;
import mate.academy.model.dto.UserResponseDto;
import mate.academy.service.RoleService;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {
    private final RoleMapper roleMapper;
    private final RoleService roleService;

    public UserMapper(RoleMapper roleMapper, RoleService roleService) {
        this.roleMapper = roleMapper;
        this.roleService = roleService;
    }

    public User mapToModel(UserRegistrationDto requestDto) {
        User user = new User();
        user.setPassword(requestDto.getPassword());
        user.setEmail(requestDto.getEmail());
        user.setRoles(Set.of(roleService.getRoleByName("USER")));
        return user;
    }

    public UserResponseDto mapToDto(User user) {
        UserResponseDto responseDto = new UserResponseDto();
        responseDto.setEmail(user.getEmail());
        List<RoleResponseDto> roles = user.getRoles()
                .stream()
                .map(roleMapper::mapToDto)
                .collect(Collectors.toList());
        responseDto.setRoles(roles);
        return responseDto;
    }
}
