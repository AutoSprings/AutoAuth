package com.autoauth.jwt;

import com.autoauth.config.AutoAuthProperties;
import com.autoauth.model.TokenPair;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import java.time.Duration;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;

/** Creates HttpOnly cookies; never returns token contents in a JavaScript-readable cookie. */
public class JwtCookies {
    private static final Pattern TOKEN_CHARACTERS = Pattern.compile("[A-Za-z0-9._-]+");
    private final AutoAuthProperties properties;
    public JwtCookies(AutoAuthProperties properties) { this.properties = properties; }

    /** Validates both cookies before adding headers; validation failures leave the response untouched. */
    public void write(HttpServletResponse response, TokenPair tokens) {
        if (tokens == null) throw new IllegalArgumentException("Token pair must not be null");
        writePair(response, access(tokens.accessToken()), refresh(tokens.refreshToken()));
    }

    public void clear(HttpServletResponse response) {
        writePair(response, cookie(properties.getCookieName(), "", Duration.ZERO),
                cookie(properties.getRefreshCookieName(), "", Duration.ZERO));
    }

    private void writePair(HttpServletResponse response, ResponseCookie access, ResponseCookie refresh) {
        String accessHeader = serialize(access);
        String refreshHeader = serialize(refresh);
        response.addHeader(HttpHeaders.SET_COOKIE, accessHeader);
        response.addHeader(HttpHeaders.SET_COOKIE, refreshHeader);
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
    }

    public ResponseCookie access(String token) {
        validateToken(token);
        return cookie(properties.getCookieName(), token, Duration.ofMinutes(properties.getExpirationMinutes()));
    }

    public ResponseCookie refresh(String token) {
        validateToken(token);
        return cookie(properties.getRefreshCookieName(), token, Duration.ofMinutes(properties.getRefreshExpirationMinutes()));
    }

    private ResponseCookie cookie(String name, String token, Duration maxAge) {
        if (!properties.isCookieEnabled()) throw new IllegalStateException("Cookie transport is disabled");
        ResponseCookie cookie = ResponseCookie.from(name, token).httpOnly(true).secure(properties.isCookieSecure())
                .sameSite(properties.getCookieSameSite()).path("/").maxAge(maxAge).build();
        serialize(cookie);
        return cookie;
    }

    private void validateToken(String token) {
        if (token == null || !TOKEN_CHARACTERS.matcher(token).matches()) {
            throw new IllegalArgumentException("Cookie token must be nonempty and contain only JWT characters");
        }
    }

    private String serialize(ResponseCookie cookie) {
        int budget = properties.getMaxCookieSize();
        if (budget <= 0) throw new IllegalArgumentException("autoauth.max-cookie-size must be positive");
        String header = cookie.toString();
        int size = header.getBytes(StandardCharsets.UTF_8).length;
        if (size > budget) {
            throw new IllegalArgumentException("Cookie '" + cookie.getName() + "' requires " + size
                    + " bytes, exceeding autoauth.max-cookie-size=" + budget);
        }
        return header;
    }
}
