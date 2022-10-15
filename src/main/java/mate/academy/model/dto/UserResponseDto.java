package mate.academy.model.dto;

import java.util.List;

public class UserResponseDto {
    private String login;
    private List<RoleResponseDto> roles;

    public String getLogin() {
        return login;
    }

    public void setLogin(String login) {
        this.login = login;
    }

    public List<RoleResponseDto> getRoles() {
        return roles;
    }

    public void setRoles(List<RoleResponseDto> roles) {
        this.roles = roles;
    }
}
