package com.autoauth.filter;

import com.autoauth.exception.JwtValidationException;
import com.autoauth.exception.TokenRevokedException;
import com.autoauth.jwt.JwtValidator;
import com.autoauth.model.AutoAuthUser;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtAuthenticationFilterTest {
    private final JwtValidator validator = mock(JwtValidator.class);
    private final FilterChain chain = mock(FilterChain.class);
    private final MockHttpServletRequest request = new MockHttpServletRequest();
    private final MockHttpServletResponse response = new MockHttpServletResponse();
    private final AutoAuthUser user = new AutoAuthUser("alice", List.of("ADMIN", "USER"), null);
    private JwtAuthenticationFilter filter;

    @BeforeEach
    void setUp() {
        filter = new JwtAuthenticationFilter(validator, "auth");
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void missingTokenContinuesWithoutAuthentication() throws Exception {
        filter.doFilter(request, response, chain);
        verifyNoInteractions(validator);
        verify(chain).doFilter(request, response);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    void bearerTokenPopulatesPrincipalAndAuthorities() throws Exception {
        request.addHeader("Authorization", "Bearer token");
        when(validator.validateAccessToken("token")).thenReturn(user);
        filter.doFilter(request, response, chain);
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication.getPrincipal()).isEqualTo(user);
        assertThat(authentication.isAuthenticated()).isTrue();
        assertThat(authentication.getAuthorities()).extracting("authority").containsExactly("ROLE_ADMIN", "ROLE_USER");
        verify(chain).doFilter(request, response);
    }

    @Test
    void readsConfiguredCookieWhenBearerTokenIsAbsent() throws Exception {
        request.setCookies(new Cookie("other", "ignored"), new Cookie("auth", "cookie-token"));
        when(validator.validateAccessToken("cookie-token")).thenReturn(user);
        filter.doFilter(request, response, chain);
        verify(validator).validateAccessToken("cookie-token");
        assertThat(SecurityContextHolder.getContext().getAuthentication().getPrincipal()).isEqualTo(user);
    }

    @Test
    void bearerTokenTakesPrecedenceOverCookie() throws Exception {
        request.addHeader("Authorization", "Bearer bearer-token");
        request.setCookies(new Cookie("auth", "cookie-token"));
        when(validator.validateAccessToken("bearer-token")).thenReturn(user);
        filter.doFilter(request, response, chain);
        verify(validator).validateAccessToken("bearer-token");
        verifyNoMoreInteractions(validator);
    }

    @Test
    void ignoresUnrelatedCookiesAndNonBearerHeaders() throws Exception {
        request.addHeader("Authorization", "Basic credentials");
        request.setCookies(new Cookie("other", "ignored"));
        filter.doFilter(request, response, chain);
        verifyNoInteractions(validator);
        verify(chain).doFilter(request, response);
    }

    @ParameterizedTest
    @MethodSource("validationFailures")
    void invalidTokensClearAuthenticationAndContinueChain(RuntimeException failure) throws Exception {
        request.addHeader("Authorization", "Bearer invalid");
        SecurityContextHolder.getContext().setAuthentication(mock(Authentication.class));
        when(validator.validateAccessToken("invalid")).thenThrow(failure);
        filter.doFilter(request, response, chain);
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        verify(chain).doFilter(request, response);
    }

    static Stream<RuntimeException> validationFailures() {
        return Stream.of(new IllegalArgumentException("invalid"), new SecurityException("invalid"),
                new JwtValidationException("expired"), new TokenRevokedException("revoked"));
    }
}
