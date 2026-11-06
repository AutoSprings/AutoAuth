package com.autoauth.jwt;

import com.autoauth.config.AutoAuthProperties;
import com.autoauth.model.TokenPair;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import java.time.Duration;

/** Creates HttpOnly cookies; never returns token contents in a JavaScript-readable cookie. */
public class JwtCookies {
    private final AutoAuthProperties properties;
    public JwtCookies(AutoAuthProperties properties) { this.properties = properties; }

    public void write(HttpServletResponse response, TokenPair tokens) {
        response.addHeader(HttpHeaders.SET_COOKIE, access(tokens.accessToken()).toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refresh(tokens.refreshToken()).toString());
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
    }

    public void clear(HttpServletResponse response) {
        response.addHeader(HttpHeaders.SET_COOKIE, cookie(properties.getCookieName(), "", Duration.ZERO).toString());
        response.addHeader(HttpHeaders.SET_COOKIE, cookie(properties.getRefreshCookieName(), "", Duration.ZERO).toString());
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
    }

    public ResponseCookie access(String token) {
        return cookie(properties.getCookieName(), token, Duration.ofMinutes(properties.getExpirationMinutes()));
    }

    public ResponseCookie refresh(String token) {
        return cookie(properties.getRefreshCookieName(), token, Duration.ofMinutes(properties.getRefreshExpirationMinutes()));
    }

    private ResponseCookie cookie(String name, String token, Duration maxAge) {
        if (!properties.isCookieEnabled()) throw new IllegalStateException("Cookie transport is disabled");
        return ResponseCookie.from(name, token).httpOnly(true).secure(properties.isCookieSecure())
                .sameSite(properties.getCookieSameSite()).path("/").maxAge(maxAge).build();
    }
}
