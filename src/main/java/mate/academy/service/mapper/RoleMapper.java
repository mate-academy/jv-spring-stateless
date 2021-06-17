package mate.academy.service.mapper;

import mate.academy.model.Role;
import mate.academy.model.dto.RoleResponseDto;
import org.springframework.stereotype.Component;

@Component
public class RoleMapper {
    public RoleResponseDto mapToDto(Role role) {
        RoleResponseDto responseDto = new RoleResponseDto();
        responseDto.setId(role.getId());
        responseDto.setName(role.getRoleName().name());
        return responseDto;
    }
}
