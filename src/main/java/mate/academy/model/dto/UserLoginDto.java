package mate.academy.model.dto;

import javax.validation.constraints.NotBlank;
import mate.academy.validation.Email;

public class UserLoginDto {
    @Email
    private String email;
    @NotBlank(message = "Password can't be null or blank!")
    private String password;

    public String getEmail() {
        return email;
    }

    public String getPassword() {
        return password;
    }
}
