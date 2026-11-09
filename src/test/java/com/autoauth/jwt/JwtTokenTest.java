package com.autoauth.jwt;

import com.autoauth.config.AutoAuthProperties;
import com.autoauth.exception.JwtValidationException;
import com.autoauth.exception.ExpiredAccessTokenException;
import com.autoauth.model.AutoAuthUser;
import com.autoauth.support.TestKeys;
import io.jsonwebtoken.*;
import org.junit.jupiter.api.Test;
import java.time.*;
import java.time.Clock;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

class JwtTokenTest {
    private final AutoAuthProperties properties = TestKeys.properties();
    private final JwtKeyProvider keys = new JwtKeyProvider(properties);
    private final Clock clock = Clock.fixed(Instant.parse("2030-01-01T00:00:00Z"), ZoneOffset.UTC);
    private final JwtGenerator generator = new JwtGenerator(keys, properties, clock);
    private final JwtValidator validator = new JwtValidator(keys, properties, clock);
    private final AutoAuthUser user = new AutoAuthUser("alice", List.of("ADMIN"), Map.of("tenant", "acme"));

    @Test
    void tokenPairRoundTripsAndSeparatesPurposes() {
        var pair = generator.generateTokenPair(user);
        assertThat(validator.validateAccessToken(pair.accessToken())).isEqualTo(user);
        assertThat(validator.validateRefreshToken(pair.refreshToken())).isEqualTo(new AutoAuthUser("alice", null, null));
        assertThatThrownBy(() -> validator.validateAccessToken(pair.refreshToken())).isInstanceOf(JwtValidationException.class);
        assertThatThrownBy(() -> validator.validateRefreshToken(pair.accessToken())).isInstanceOf(JwtValidationException.class);
        Claims access = parse(pair.accessToken());
        Claims refresh = parse(pair.refreshToken());
        assertThat(access.getIssuedAt().toInstant()).isEqualTo(clock.instant());
        assertThat(access.getExpiration().toInstant()).isEqualTo(clock.instant().plus(Duration.ofMinutes(15)));
        assertThat(refresh.getExpiration().toInstant()).isEqualTo(clock.instant().plus(Duration.ofMinutes(10080)));
        assertThat(access.getId()).isNotEqualTo(refresh.getId());
    }

    @Test
    void customClaimsCannotOverwriteIdentityOrSecurityClaims() {
        for (String name : List.of("sub", "roles", "type", "exp", "iat", "nbf", "jti", "iss", "aud")) {
            assertThatThrownBy(() -> generator.generateAccessToken(
                    new AutoAuthUser("alice", null, Map.of(name, "override")))).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void requiresExpirationSubjectIdAndStringRoles() {
        for (String name : List.of("exp", "sub", "jti", "type")) {
            assertThatThrownBy(() -> validator.validateAccessToken(sign(builder().claim(name, null))))
                    .isInstanceOf(JwtValidationException.class);
        }
        for (Object roles : List.of("ADMIN", List.of(7), List.of("ADMIN", 7))) {
            assertThatThrownBy(() -> validator.validateAccessToken(sign(builder().claim("roles", roles))))
                    .isInstanceOf(JwtValidationException.class);
        }
    }

    @Test
    void rejectsWrongSignatureIssuerAudienceAndAlgorithm() {
        assertThatThrownBy(() -> validator.validateAccessToken(
                builder().signWith(TestKeys.generate("RSA").getPrivate(), Jwts.SIG.RS256).compact()))
                .isInstanceOf(JwtValidationException.class);
        assertThatThrownBy(() -> validator.validateAccessToken(sign(builder().issuer("other"))))
                .isInstanceOf(JwtValidationException.class);
        assertThatThrownBy(() -> validator.validateAccessToken(sign(builder().audience().clear().add("other").and())))
                .isInstanceOf(JwtValidationException.class);
        assertThatThrownBy(() -> validator.validateAccessToken(builder().signWith(keys.getPrivateKey(), Jwts.SIG.RS512).compact()))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void rejectsMalformedUnsignedTaskAndOversizedTokens() {
        for (String value : List.of("", " ", "bad", "a.b.c", "a.b.c.d", "x".repeat(16385))) {
            assertThatThrownBy(() -> validator.validateAccessToken(value)).isInstanceOf(JwtValidationException.class);
        }
        assertThatThrownBy(() -> validator.validateAccessToken(null)).isInstanceOf(JwtValidationException.class);
        assertThatThrownBy(() -> validator.validateAccessToken(builder().compact()))
                .isInstanceOf(JwtValidationException.class);
        assertThatThrownBy(() -> validator.validateAccessToken(sign(builder().claim("type", "task"))))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void expirationAllowsOnlyConfiguredThirtySecondSkew() {
        for (String type : List.of("access", "refresh")) {
            for (int secondsAgo : List.of(0, 29, 30)) {
                String token = sign(builder().claim("type", type)
                        .expiration(Date.from(clock.instant().minusSeconds(secondsAgo))));
                assertThat(validatePurpose(token, type)).isNotNull();
            }
            String expired = sign(builder().claim("type", type)
                    .expiration(Date.from(clock.instant().minusSeconds(31))));
            assertThatThrownBy(() -> validatePurpose(expired, type)).isInstanceOf(JwtValidationException.class);
        }
    }

    @Test
    void onlyOtherwiseValidExpiredAccessTokensReceiveRecoveryClassification() {
        assertThatThrownBy(() -> validator.validateAccessToken(sign(expiredBuilder())))
                .isExactlyInstanceOf(ExpiredAccessTokenException.class);
        assertThatThrownBy(() -> validator.validateRefreshToken(sign(expiredBuilder().claim("type", "refresh"))))
                .isInstanceOf(JwtValidationException.class).isNotInstanceOf(ExpiredAccessTokenException.class);
    }

    @Test
    void expiryDoesNotMaskInvalidClaimsAlgorithmOrSignature() {
        List<String> invalid = List.of(
                sign(expiredBuilder().issuer("other")),
                sign(expiredBuilder().issuer(null)),
                sign(expiredBuilder().audience().clear().add("other").and()),
                sign(expiredBuilder().claim("aud", null)),
                sign(expiredBuilder().claim("type", "refresh")),
                sign(expiredBuilder().claim("type", "task")),
                sign(expiredBuilder().claim("type", null)),
                sign(expiredBuilder().subject(null)),
                sign(expiredBuilder().subject(" ")),
                sign(expiredBuilder().id(null)),
                sign(expiredBuilder().claim("roles", List.of(7))),
                sign(expiredBuilder().claim("roles", List.of("ROLE_"))),
                sign(expiredBuilder().notBefore(Date.from(clock.instant().plusSeconds(31)))),
                expiredBuilder().signWith(keys.getPrivateKey(), Jwts.SIG.RS512).compact(),
                expiredBuilder().signWith(TestKeys.generate("RSA").getPrivate(), Jwts.SIG.RS256).compact());
        for (String token : invalid) {
            assertThatThrownBy(() -> validator.validateAccessToken(token))
                    .isInstanceOf(JwtValidationException.class).isNotInstanceOf(ExpiredAccessTokenException.class);
        }
    }

    private JwtBuilder expiredBuilder() {
        return builder().expiration(Date.from(clock.instant().minusSeconds(31)));
    }

    @Test
    void notBeforeAllowsOnlyConfiguredThirtySecondSkew() {
        for (String type : List.of("access", "refresh")) {
            for (int secondsAhead : List.of(0, 29, 30)) {
                String token = sign(builder().claim("type", type)
                        .notBefore(Date.from(clock.instant().plusSeconds(secondsAhead))));
                assertThat(validatePurpose(token, type)).isNotNull();
            }
            String premature = sign(builder().claim("type", type)
                    .notBefore(Date.from(clock.instant().plusSeconds(31))));
            assertThatThrownBy(() -> validatePurpose(premature, type)).isInstanceOf(JwtValidationException.class);
        }
    }

    private AutoAuthUser validatePurpose(String token, String type) {
        return "access".equals(type) ? validator.validateAccessToken(token) : validator.validateRefreshToken(token);
    }

    private JwtBuilder builder() {
        return Jwts.builder().issuer(properties.getIssuer()).audience().add(properties.getAudience()).and()
                .subject("alice").id("test-id").claim("type", "access").claim("roles", List.of("ADMIN"))
                .expiration(Date.from(clock.instant().plusSeconds(60)));
    }
    private String sign(JwtBuilder builder) { return builder.signWith(keys.getPrivateKey(), Jwts.SIG.RS256).compact(); }
    private Claims parse(String token) {
        return Jwts.parser().verifyWith(keys.getPublicKey()).clock(() -> Date.from(clock.instant())).build()
                .parseSignedClaims(token).getPayload();
    }

    @Test
    void nullCustomClaimsAreSafelyOmittedByTheParser() {
        String payload = "{\"iss\":\"autoauth-default-issuer\",\"aud\":[\"autoauth-default-audience\"],"
                + "\"sub\":\"alice\",\"jti\":\"id\",\"type\":\"access\","
                + "\"exp\":1893456060,\"tenant\":null}";
        String token = Jwts.builder().content(payload).signWith(keys.getPrivateKey(), Jwts.SIG.RS256).compact();
        assertThat(validator.validateAccessToken(token).customClaims()).doesNotContainKey("tenant");
    }

}
