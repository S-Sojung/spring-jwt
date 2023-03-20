package shop.mtcoding.jwtstudy.config.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;

import shop.mtcoding.jwtstudy.config.auth.JwtProvider;
import shop.mtcoding.jwtstudy.config.auth.LoginUser;

public class JwtVerifyFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;

        // String jwt = req.getHeader(JwtProvider.HEADER).split(" ")[1];
        String prefixJwt = req.getHeader(JwtProvider.HEADER);
        String jwt = prefixJwt.replace(JwtProvider.TOKEN_PREFIX, "");

        try {
            DecodedJWT decodedJWT = JwtProvider.verify(jwt);
            int id = decodedJWT.getClaim("id").asInt();
            String role = decodedJWT.getClaim("role").asString();

            HttpSession session = req.getSession();
            LoginUser loginUser = LoginUser.builder().id(id).role(role).build();
            // 내부적인 권한처리를 위해 세션에 넣어줌
            session.setAttribute("loginUser", loginUser);
            chain.doFilter(req, resp);

        } catch (SignatureVerificationException sve) {
            resp.setStatus(401);
            resp.setContentType("text/plain; charset=utf-8");
            resp.getWriter().println("로그인 다시해");
        } catch (TokenExpiredException tee) {
            resp.setContentType("text/plain; charset=utf-8");
            resp.getWriter().println("로그인 다시해");
        }
    }

    private void myFailResponse(HttpServletResponse resp, Exception e) {

    }

}
