package com.autoauth.jwt;

import com.autoauth.config.AutoAuthProperties;
import com.autoauth.exception.JwtValidationException;
import com.autoauth.exception.ExpiredAccessTokenException;
import com.autoauth.model.AutoAuthUser;
import io.jsonwebtoken.*;
import java.time.Clock;
import java.util.*;

/** Verifies signatures and the access/refresh claim contract; contains no session store. */
public class JwtValidator {
    private static final int CLOCK_SKEW_SECONDS = 30;
    private final JwtParser parser;
    private final int maxLength;
    private final String issuer;
    private final String audience;
    private final Clock clock;

    public JwtValidator(JwtKeyProvider keys, AutoAuthProperties properties) {
        this(keys, properties, Clock.systemUTC());
    }

    public JwtValidator(JwtKeyProvider keys, AutoAuthProperties properties, Clock clock) {
        properties.validate();
        maxLength = properties.getMaxTokenLength();
        issuer = properties.getIssuer();
        audience = properties.getAudience();
        this.clock = clock;
        parser = Jwts.parser().verifyWith(keys.getPublicKey())
                .clock(() -> Date.from(clock.instant())).clockSkewSeconds(CLOCK_SKEW_SECONDS)
                .requireIssuer(issuer).requireAudience(audience).build();
    }

    public AutoAuthUser validateAccessToken(String token) { return validate(token, "access"); }
    public AutoAuthUser validateRefreshToken(String token) { return validate(token, "refresh"); }

    private AutoAuthUser validate(String token, String expectedType) {
        if (token == null || token.isBlank() || token.length() > maxLength) {
            throw new JwtValidationException("Missing or oversized JWT");
        }
        try {
            try {
                Jws<Claims> signed = parser.parseSignedClaims(token);
                return identity(signed.getHeader(), signed.getPayload(), expectedType);
            } catch (ExpiredJwtException exception) {
                // JJWT has verified the signature, but checks expiry before nbf/required claims.
                // Never classify a wrong-purpose, wrong-issuer, or otherwise invalid JWT as recoverable.
                identity(exception.getHeader(), exception.getClaims(), expectedType);
                if ("access".equals(expectedType)) throw new ExpiredAccessTokenException(exception);
                throw exception;
            }
        } catch (JwtException | IllegalArgumentException exception) {
            throw new JwtValidationException("JWT validation failed", exception);
        }
    }

    private AutoAuthUser identity(Header header, Claims claims, String expectedType) {
        if (!"RS256".equals(header.get("alg"))) throw new JwtValidationException("Only RS256 tokens are supported");
        if (!issuer.equals(claims.getIssuer()) || claims.getAudience() == null || !claims.getAudience().contains(audience)) {
            throw new JwtValidationException("Invalid JWT issuer or audience");
        }
        Date notBefore = claims.getNotBefore();
        if (notBefore != null && notBefore.toInstant().isAfter(clock.instant().plusSeconds(CLOCK_SKEW_SECONDS))) {
            throw new JwtValidationException("JWT is not active yet");
        }
        if (!expectedType.equals(claims.get("type", String.class))) throw new JwtValidationException("Invalid token type");
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
    }
}
