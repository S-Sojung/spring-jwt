package shop.mtcoding.jwtstudy.example;

import java.util.Date;

import org.junit.jupiter.api.Test;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;

//Json Web Token  : 대칭키 사용
public class JwtTest {

    // ABC(메타코딩) => 1313AB
    // ABC(메타) => 5335KD

    // 로그인이 완료되면 1313AB 라는 토큰이 생성됨
    // 세션에다가 유저 정보를 넣는게 아니라 토큰을 생성!!!
    // 키는 나만 알고 있음 된다. 내가 잠그고 내가 연다.
    // 클라이언트에게 토큰 주고, 클라이언트는 토큰으로 서버에게 인증요청을 한다.
    // 서버는 가지고 있는 대칭키로 검증만 하면 된다.
    // 그렇게 대칭키로 열린 정보에는 user의 id와 권한 정보만 있으면 된다.

    @Test
    public void createJwt_test() {
        // given

        // when
        String jwt = JWT.create()
                .withSubject("토큰제목")
                .withExpiresAt(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 7)) // 토큰만료 시간
                .withClaim("id", 1) // 값이 들어가는 것
                .withClaim("role", "guest")
                .sign(Algorithm.HMAC512("메타코딩"));
        // 암호화 소금 치기... 이건 절대 노출 되면 안됨
        System.out.println(jwt);

        System.out.println(JWT.decode(jwt));
        // then
    }
}