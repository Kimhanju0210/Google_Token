package org.example.ntoken.oauth.exception;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.naming.AuthenticationException;
import java.io.IOException;

@Slf4j
public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException
    ) throws IOException, ServletException {
        authException.printStackTrace();
        log.info("Responding with unauthorized error. Message := {}", authException.getMessage());
        response.sendError(
                HttpServletResponse.SC_UNAUTHORIZED,
                authException.getLocalizedMessage()
        );
    }
}
