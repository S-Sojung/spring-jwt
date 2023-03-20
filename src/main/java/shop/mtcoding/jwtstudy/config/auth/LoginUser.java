package shop.mtcoding.jwtstudy.config.auth;

import lombok.Builder;
import lombok.Getter;

//setter 필요없다.
@Getter
public class LoginUser {
    private Integer id;
    private String role;

    @Builder
    public LoginUser(Integer id, String role) {
        this.id = id;
        this.role = role;
    }
}
