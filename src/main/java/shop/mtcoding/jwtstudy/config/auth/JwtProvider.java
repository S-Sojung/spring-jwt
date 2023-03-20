package shop.mtcoding.jwtstudy.config.auth;

import java.util.Date;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;

import shop.mtcoding.jwtstudy.model.User;

public class JwtProvider {

    private static final String SUBJECT = "jwtstudy";
    private static final int EXP = 1000 * 60 * 60;
    public static final String TOKEN_PREFIX = "Bearer "; // !!! 주의 !!! => 한칸 띄워주기
    public static final String HEADER = "Authorization";
    private static final String SECRET = "메타코딩";
    // 시크릿은 나중에 운영체제의 환경변수로 작성
    // echo %~~%; 으로 환경변수 확인 가능...
    // System.getenv();

    public static String create(User user) { // 세션에는 LoginUser를 넣고, 여기에는 User오브젝트가 필요하다.
        String jwt = JWT.create()
                .withSubject(SUBJECT)
                .withExpiresAt(new Date(System.currentTimeMillis() + EXP)) // 토큰만료 시간
                .withClaim("id", user.getId()) // 값이 들어가는 것
                .withClaim("role", user.getRole())
                .sign(Algorithm.HMAC512(SECRET));

        return TOKEN_PREFIX + jwt;
    }

    public static DecodedJWT verify(String jwt) throws SignatureVerificationException, TokenExpiredException {

        DecodedJWT decodedJWT = JWT.require(Algorithm.HMAC512("메타코딩")).build().verify(jwt);

        // } catch (SignatureVerificationException sve) {
        // System.out.println("검증 실패 , 토큰 틀림 " + sve); // 위조
        // } catch (TokenExpiredException tee) {
        // System.out.println("토큰 시간 만료" + tee); // 오래됨. -> 갱신하지말고 다시 로그인하자.
        // 얘가 에러 잡아서 보내면 안됨!!! 핸들러가 잡을 수 있도록 throws를 날려줌

        // 역할은 검증만!!! 세션은 다른데서~!~!

        return decodedJWT;
    }
}
