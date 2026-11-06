package com.autoauth.filter;

import com.autoauth.config.AutoAuthProperties;
import com.autoauth.exception.AutoAuthAuthenticationEntryPoint;
import com.autoauth.exception.JwtValidationException;
import com.autoauth.jwt.JwtValidator;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

/** Bearer headers take precedence; refresh cookies are never used to authenticate requests. */
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtValidator validator;
    private final AutoAuthProperties properties;

    public JwtAuthenticationFilter(JwtValidator validator, AutoAuthProperties properties) {
        this.validator = validator;
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        try {
            String token = extractToken(request);
            if (token != null) {
                var user = validator.validateAccessToken(token);
                var authorities = user.roles().stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)).toList();
                SecurityContextHolder.getContext().setAuthentication(
                        new UsernamePasswordAuthenticationToken(user, null, authorities));
            }
        } catch (JwtValidationException | IllegalArgumentException exception) {
            SecurityContextHolder.clearContext();
            new AutoAuthAuthenticationEntryPoint().commence(request, response,
                    new BadCredentialsException("Invalid access token", exception));
            return;
        }
        chain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.regionMatches(true, 0, "Bearer", 0, 6)) {
            if (header.length() < 8 || header.charAt(6) != ' ') throw new JwtValidationException("Invalid bearer header");
            return header.substring(7);
        }
        if (properties.isCookieEnabled() && request.getCookies() != null) {
            String token = null;
            for (Cookie cookie : request.getCookies()) {
                if (properties.getCookieName().equals(cookie.getName())) {
                    if (token != null) throw new JwtValidationException("Duplicate access cookies");
                    token = cookie.getValue();
                }
            }
            return token;
        }
        return null;
    }
}
