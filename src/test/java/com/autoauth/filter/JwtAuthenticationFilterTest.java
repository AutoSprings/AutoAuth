package com.autoauth.filter;

import com.autoauth.config.AutoAuthProperties;
import com.autoauth.exception.JwtValidationException;
import com.autoauth.jwt.JwtValidator;
import com.autoauth.model.AutoAuthUser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.*;
import org.springframework.security.core.context.SecurityContextHolder;
import java.util.List;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtAuthenticationFilterTest {
    private final JwtValidator validator = mock(JwtValidator.class);
    private final FilterChain chain = mock(FilterChain.class);
    private final AutoAuthProperties properties = new AutoAuthProperties();
    private final MockHttpServletRequest request = new MockHttpServletRequest();
    private final MockHttpServletResponse response = new MockHttpServletResponse();
    private final AutoAuthUser user = new AutoAuthUser("alice", List.of("ADMIN"), null);
    @AfterEach void clear() { SecurityContextHolder.clearContext(); }

    @Test
    void bearerTakesPrecedenceAndPopulatesSpringAuthorities() throws Exception {
        request.addHeader("Authorization", "bearer token");
        request.setCookies(new Cookie(properties.getCookieName(), "cookie"));
        when(validator.validateAccessToken("token")).thenReturn(user);
        filter();
        verify(validator).validateAccessToken("token");
        verifyNoMoreInteractions(validator);
        assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities())
                .extracting("authority").containsExactly("ROLE_ADMIN");
    }
    @Test
    void cookieModeAcceptsOnlyAccessCookie() throws Exception {
        request.setCookies(new Cookie(properties.getRefreshCookieName(), "refresh"));
        filter();
        verifyNoInteractions(validator);
        request.setCookies(new Cookie(properties.getCookieName(), "access"));
        when(validator.validateAccessToken("access")).thenReturn(user);
        filter();
        verify(validator).validateAccessToken("access");
    }
    @Test
    void bearerOnlyModeIgnoresCookies() throws Exception {
        properties.setTransport(AutoAuthProperties.Transport.BEARER);
        request.setCookies(new Cookie(properties.getCookieName(), "access"));
        filter();
        verifyNoInteractions(validator);
    }
    @Test
    void invalidBearerNeverFallsBackToCookieAndStopsChain() throws Exception {
        request.addHeader("Authorization", "Bearer invalid");
        request.setCookies(new Cookie(properties.getCookieName(), "access"));
        when(validator.validateAccessToken("invalid")).thenThrow(new JwtValidationException("invalid"));
        filter();
        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer");
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verifyNoInteractions(chain);
    }
    @Test
    void duplicateCookiesAreRejected() throws Exception {
        request.setCookies(new Cookie(properties.getCookieName(), "one"), new Cookie(properties.getCookieName(), "two"));
        filter();
        assertThat(response.getStatus()).isEqualTo(401);
        verifyNoInteractions(chain, validator);
    }
    private void filter() throws Exception { new JwtAuthenticationFilter(validator, properties).doFilter(request, response, chain); }
}
