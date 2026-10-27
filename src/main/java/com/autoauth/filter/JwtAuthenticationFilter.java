package com.autoauth.filter;

import com.autoauth.jwt.JwtValidator;
import com.autoauth.model.AutoAuthUser;
import com.autoauth.exception.JwtValidationException;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

public class JwtAuthenticationFilter extends OncePerRequestFilter{

    private final JwtValidator jwtValidator;
    private final String cookieName;

    public JwtAuthenticationFilter(JwtValidator jwtValidator, String cookieName) {
        this.jwtValidator = jwtValidator;
        this.cookieName = cookieName;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException
    {
        String token = null;

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
        }

        if (token == null && cookieName != null && !cookieName.isBlank()) {
            token = extractTokenFromCookie(request, cookieName);
        }

        if (token == null) {
            filterChain.doFilter(request, response);
            return;
        }

        try {

            AutoAuthUser user = jwtValidator.validateAccessToken(token);

            List<SimpleGrantedAuthority> authorities = user.roles().stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .toList();

            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(user, null, authorities);

            SecurityContextHolder.getContext().setAuthentication(authentication);

        } catch (JwtValidationException | AuthenticationException | IllegalArgumentException | SecurityException e) {

            SecurityContextHolder.clearContext();

        }

        filterChain.doFilter(request,response);

    }

    private String extractTokenFromCookie(HttpServletRequest request, String cookieName) {

        Cookie[] cookies = request.getCookies();
        if (cookies != null) {

            for (Cookie cookie: cookies) {
                if (cookieName.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }

        }
        return null;
    }

}
