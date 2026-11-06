package com.autoauth.jwt;

import com.autoauth.config.AutoAuthProperties;
import com.autoauth.model.AutoAuthUser;
import com.autoauth.model.TokenPair;
import io.jsonwebtoken.Jwts;
import java.time.Clock;
import java.time.Duration;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

/** Issues access and refresh JWTs. Login and refresh-session policy belong to the application. */
public class JwtGenerator {
    private static final Set<String> RESERVED = Set.of("sub", "roles", "type", "exp", "iat", "nbf", "jti", "iss", "aud");
    private final JwtKeyProvider keys;
    private final AutoAuthProperties properties;
    private final Clock clock;

    public JwtGenerator(JwtKeyProvider keys, AutoAuthProperties properties) {
        this(keys, properties, Clock.systemUTC());
    }

    public JwtGenerator(JwtKeyProvider keys, AutoAuthProperties properties, Clock clock) {
        properties.validate();
        this.keys = keys;
        this.properties = properties;
        this.clock = clock;
    }

    public String generateAccessToken(AutoAuthUser user) {
        if (user.customClaims().keySet().stream().anyMatch(RESERVED::contains)) {
            throw new IllegalArgumentException("Custom claims must not replace reserved JWT claims");
        }
        return generate(user, "access", properties.getExpirationMinutes(), true);
    }

    public String generateRefreshToken(AutoAuthUser user) {
        return generate(user, "refresh", properties.getRefreshExpirationMinutes(), false);
    }

    private String generate(AutoAuthUser user, String type, long minutes, boolean includeClaims) {
        var now = clock.instant();
        var builder = Jwts.builder().header().keyId(keys.getKid()).and()
                .issuer(properties.getIssuer()).audience().add(properties.getAudience()).and()
                .subject(user.userId()).id(UUID.randomUUID().toString()).claim("type", type)
                .issuedAt(Date.from(now)).expiration(Date.from(now.plus(Duration.ofMinutes(minutes))));
        if (includeClaims) {
            builder.claim("roles", user.roles());
            user.customClaims().forEach(builder::claim);
        }
        String token = builder.signWith(keys.getPrivateKey(), Jwts.SIG.RS256).compact();
        if (token.length() > properties.getMaxTokenLength()) {
            throw new IllegalArgumentException("Generated JWT exceeds autoauth.max-token-length");
        }
        return token;
    }

    public TokenPair generateTokenPair(AutoAuthUser user) {
        return new TokenPair(generateAccessToken(user), generateRefreshToken(user));
    }
}
