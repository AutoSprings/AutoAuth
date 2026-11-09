package com.autoauth.filter;

import com.autoauth.config.AutoAuthProperties;
import com.autoauth.exception.AutoAuthAuthenticationEntryPoint;
import com.autoauth.exception.JwtValidationException;
import com.autoauth.exception.ExpiredAccessTokenException;
import com.autoauth.jwt.JwtValidator;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

/** Bearer headers take precedence; refresh cookies are never used to authenticate requests. */
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtValidator validator;
    private final AutoAuthProperties properties;
    private final RequestMatcher publicRequests;

    // Stateless authentication must be rebuilt on the container's continuation thread.
    @Override
    protected boolean shouldNotFilterAsyncDispatch() { return false; }

    @Override
    protected boolean shouldNotFilterErrorDispatch() { return false; }

    public JwtAuthenticationFilter(JwtValidator validator, AutoAuthProperties properties) {
        this(validator, properties, request -> false);
    }

    /**
     * @param validator access-token validator; expiry classification must preserve all other checks
     * @param properties token transport settings
     * @param publicRequests the same anonymous-request matcher used by the owning security chain
     */
    public JwtAuthenticationFilter(JwtValidator validator, AutoAuthProperties properties, RequestMatcher publicRequests) {
        this.validator = validator;
        this.properties = properties;
        this.publicRequests = java.util.Objects.requireNonNull(publicRequests, "publicRequests");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Credential credential = null;
        try {
            credential = extractToken(request);
            if (credential != null) {
                var user = validator.validateAccessToken(credential.token());
                var authorities = user.roles().stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role)).toList();
                SecurityContextHolder.getContext().setAuthentication(
                        new UsernamePasswordAuthenticationToken(user, null, authorities));
            }
        } catch (ExpiredAccessTokenException exception) {
            SecurityContextHolder.clearContext();
            if (credential == null || !credential.fromCookie() || !publicRequests.matches(request)) {
                reject(request, response, exception);
                return;
            }
            // Continue anonymously; the application still owns credentials/refresh validation and CSRF still applies.
        } catch (JwtValidationException | IllegalArgumentException exception) {
            reject(request, response, exception);
            return;
        }
        chain.doFilter(request, response);
    }

    private void reject(HttpServletRequest request, HttpServletResponse response, Exception exception) throws IOException {
        SecurityContextHolder.clearContext();
        new AutoAuthAuthenticationEntryPoint().commence(request, response,
                new BadCredentialsException("Invalid access token", exception));
    }

    private Credential extractToken(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.regionMatches(true, 0, "Bearer", 0, 6)) {
            if (header.length() < 8 || header.charAt(6) != ' ') throw new JwtValidationException("Invalid bearer header");
            return new Credential(header.substring(7), false);
        }
        if (properties.isCookieEnabled() && request.getCookies() != null) {
            Credential token = null;
            for (Cookie cookie : request.getCookies()) {
                if (properties.getCookieName().equals(cookie.getName())) {
                    if (token != null) throw new JwtValidationException("Duplicate access cookies");
                    token = new Credential(cookie.getValue(), true);
                }
            }
            return token;
        }
        return null;
    }

    private record Credential(String token, boolean fromCookie) {}
}
