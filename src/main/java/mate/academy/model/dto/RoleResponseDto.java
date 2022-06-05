package mate.academy.model.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class RoleResponseDto {
    private Long id;
    private String name;

    public RoleResponseDto(Long id, String name) {
        this.id = id;
        this.name = name;
    }

    public RoleResponseDto() {
    }
}
