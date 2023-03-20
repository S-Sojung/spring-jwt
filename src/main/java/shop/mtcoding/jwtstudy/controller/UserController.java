package shop.mtcoding.jwtstudy.controller;

import java.util.Optional;

import javax.servlet.http.HttpSession;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import shop.mtcoding.jwtstudy.config.auth.JwtProvider;
import shop.mtcoding.jwtstudy.config.auth.LoginUser;
import shop.mtcoding.jwtstudy.model.User;
import shop.mtcoding.jwtstudy.model.UserRepository;

@RequiredArgsConstructor
@RestController
public class UserController {
    private final UserRepository userRepository;
    private final HttpSession session;

    @GetMapping("/user") // 인증 필요
    public ResponseEntity<?> user() {
        LoginUser loginUser = (LoginUser) session.getAttribute("loginUser");
        if (loginUser.getId() == 1) {
            return ResponseEntity.ok().body("접근 성공");
        } else {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("접근 권한 없음");
        }
    }

    @GetMapping("/") // 인증 불필요
    public ResponseEntity<?> main() {
        return ResponseEntity.ok().body("접근 성공");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(User user) {
        Optional<User> userOP = userRepository.findByUsernameAndPassword(user.getUsername(), user.getPassword());
        // Optional은 null 일수도 있다 라는 의미. 꼭 null 처리를 해야한다.
        if (userOP.isPresent()) { // 값이 있다.
            String jwt = JwtProvider.create(userOP.get());
            return ResponseEntity.ok().header(JwtProvider.HEADER, jwt).body("로그인 성공");
        } else { // 값이 없다.
            return ResponseEntity.badRequest().build();
        }
    }
}
