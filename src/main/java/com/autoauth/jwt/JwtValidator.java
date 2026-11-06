package com.autoauth.jwt;

import com.autoauth.config.AutoAuthProperties;
import com.autoauth.exception.JwtValidationException;
import com.autoauth.model.AutoAuthUser;
import io.jsonwebtoken.*;
import java.time.Clock;
import java.util.*;

/** Verifies signatures and the access/refresh claim contract; contains no session store. */
public class JwtValidator {
    private final JwtParser parser;
    private final int maxLength;

    public JwtValidator(JwtKeyProvider keys, AutoAuthProperties properties) {
        this(keys, properties, Clock.systemUTC());
    }

    public JwtValidator(JwtKeyProvider keys, AutoAuthProperties properties, Clock clock) {
        properties.validate();
        maxLength = properties.getMaxTokenLength();
        parser = Jwts.parser().verifyWith(keys.getPublicKey())

                .clock(() -> Date.from(clock.instant())).clockSkewSeconds(30)
                .requireIssuer(properties.getIssuer()).requireAudience(properties.getAudience()).build();
    }

    public AutoAuthUser validateAccessToken(String token) { return validate(token, "access"); }
    public AutoAuthUser validateRefreshToken(String token) { return validate(token, "refresh"); }

    private AutoAuthUser validate(String token, String expectedType) {
        if (token == null || token.isBlank() || token.length() > maxLength) {
            throw new JwtValidationException("Missing or oversized JWT");
        }
        try {
            Jws<Claims> signed = parser.parseSignedClaims(token);
            if (!"RS256".equals(signed.getHeader().getAlgorithm())) {
                throw new JwtValidationException("Only RS256 tokens are supported");
            }
            Claims claims = signed.getPayload();
            if (!expectedType.equals(claims.get("type", String.class))) {
                throw new JwtValidationException("Invalid token type");
            }
            if (claims.getExpiration() == null || claims.getSubject() == null || claims.getSubject().isBlank()
                    || claims.getId() == null || claims.getId().isBlank()) {
                throw new JwtValidationException("JWT requires exp, sub, and jti claims");
            }
            Object rawRoles = claims.get("roles");
            List<String> roles = List.of();
            if (rawRoles != null) {
                if (!(rawRoles instanceof List<?> list) || list.stream().anyMatch(role -> !(role instanceof String))) {
                    throw new JwtValidationException("JWT roles must be an array of strings");
                }
                roles = ((List<?>) rawRoles).stream().map(String.class::cast).toList();
            }
            Map<String, Object> custom = new HashMap<>(claims);
            Set.of("sub", "roles", "type", "exp", "iat", "nbf", "jti", "iss", "aud").forEach(custom::remove);
            return new AutoAuthUser(claims.getSubject(), roles, custom);
        } catch (JwtException | IllegalArgumentException exception) {
            throw new JwtValidationException("JWT validation failed", exception);
        }
    }
}
