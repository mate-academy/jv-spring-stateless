package mate.academy.service.mapper;

import java.util.HashSet;
import java.util.List;
import mate.academy.model.User;
import mate.academy.model.dto.RoleResponseDto;
import mate.academy.model.dto.UserRegistrationDto;
import mate.academy.model.dto.UserResponseDto;
import org.springframework.stereotype.Component;

@Component
public class UserMapper {
    private final RoleMapper roleMapper;

    public UserMapper(RoleMapper roleMapper) {
        this.roleMapper = roleMapper;
    }

    public User mapToModel(UserRegistrationDto requestDto) {
        User user = new User();
        user.setPassword(requestDto.getPassword());
        user.setEmail(requestDto.getEmail());
        user.setRoles(new HashSet<>());
        return user;
    }

    public UserResponseDto mapToDto(User user) {
        UserResponseDto responseDto = new UserResponseDto();
        responseDto.setEmail(user.getEmail());
        List<RoleResponseDto> roles = user.getRoles()
                .stream()
                .map(roleMapper::mapToDto)
                .toList();
        responseDto.setRoles(roles);
        return responseDto;
    }
}
