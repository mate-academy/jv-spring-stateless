package mate.academy.model.dto;

import java.util.List;

public class UserResponseDto {
    private String login;
    private List<RoleResponseDto> roles;

    public String getEmail() {
        return login;
    }

    public void setEmail(String email) {
        this.login = email;
    }

    public List<RoleResponseDto> getRoles() {
        return roles;
    }

    public void setRoles(List<RoleResponseDto> roles) {
        this.roles = roles;
    }
}
