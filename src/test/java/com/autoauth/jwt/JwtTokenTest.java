package com.autoauth.jwt;

import com.autoauth.blacklist.CafeTokenBlackList;
import com.autoauth.blacklist.TokenBlackList;
import com.autoauth.config.AutoAuthProperties;
import com.autoauth.exception.JwtValidationException;
import com.autoauth.exception.TokenRevokedException;
import com.autoauth.model.AutoAuthUser;
import com.autoauth.model.TokenPair;
import com.autoauth.support.TestKeys;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class JwtTokenTest {
    private AutoAuthProperties properties;
    private JwtKeyProvider keys;
    private CafeTokenBlackList blacklist;
    private JwtGenerator generator;
    private JwtValidator validator;
    private final AutoAuthUser user = new AutoAuthUser("user-123", List.of("ADMIN", "USER"), Map.of("tenant", "acme"));

    @BeforeEach
    void setUp() {
        properties = TestKeys.properties();
        keys = new JwtKeyProvider(properties);
        blacklist = new CafeTokenBlackList();
        generator = new JwtGenerator(keys, properties);
        validator = new JwtValidator(keys, blacklist, properties);
    }

    @Test
    void accessTokenRoundTripsUserAndCustomClaims() {
        String token = generator.generateAccessToken(user);
        assertThat(validator.validateAccessToken(token)).isEqualTo(user);
        var parsed = Jwts.parser().verifyWith(keys.getPublicKey()).build().parseSignedClaims(token);
        assertThat(parsed.getHeader().getKeyId()).isEqualTo(keys.getKid());
        assertThat(parsed.getHeader().getAlgorithm()).isEqualTo("RS256");
        assertThat(parsed.getPayload().getIssuer()).isEqualTo(properties.getIssuer());
        assertThat(parsed.getPayload().getAudience()).containsExactly(properties.getAudience());
        assertThat(parsed.getPayload().getId()).isNotBlank();
        assertThat(parsed.getPayload().getExpiration().getTime() - parsed.getPayload().getIssuedAt().getTime())
                .isEqualTo(Duration.ofMinutes(properties.getExpirationMinutes()).toMillis());
    }

    @Test
    void tokenPairContainsDistinctAccessAndRefreshTokens() {
        TokenPair pair = generator.generateTokenPair(user);
        assertThat(pair.accessToken()).isNotEqualTo(pair.refreshToken());
        assertThat(validator.validateAccessToken(pair.accessToken())).isEqualTo(user);
        assertThat(validator.validateRefreshToken(pair.refreshToken()))
                .isEqualTo(new AutoAuthUser(user.userId(), List.of(), Map.of()));
        Claims refresh = Jwts.parser().verifyWith(keys.getPublicKey()).build()
                .parseSignedClaims(pair.refreshToken()).getPayload();
        assertThat(refresh.getExpiration().getTime() - refresh.getIssuedAt().getTime())
                .isEqualTo(Duration.ofMinutes(properties.getRefreshExpirationMinutes()).toMillis());
    }

    @Test
    void taskTokenUsesRequestedLifetime() {
        String token = generator.generateTaskToken(user, 3);
        assertThat(validator.validateTaskToken(token)).isEqualTo(user);
        Claims claims = Jwts.parser().verifyWith(keys.getPublicKey()).build().parseSignedClaims(token).getPayload();
        assertThat(claims.getExpiration().getTime() - claims.getIssuedAt().getTime())
                .isEqualTo(Duration.ofMinutes(3).toMillis());
    }

    @Test
    void rejectsTokensUsedForTheWrongPurpose() {
        assertThatThrownBy(() -> validator.validateAccessToken(generator.generateRefreshToken(user)))
                .isInstanceOf(JwtValidationException.class).hasMessageContaining("Invalid token type");
        assertThatThrownBy(() -> validator.validateRefreshToken(generator.generateAccessToken(user)))
                .isInstanceOf(JwtValidationException.class);
        assertThatThrownBy(() -> validator.validateTaskToken(generator.generateAccessToken(user)))
                .isInstanceOf(JwtValidationException.class);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "not-a-jwt", "one.two", "one.two.three.four", "!.e30.signature", "bnVsbA.e30.signature"})
    void rejectsMissingOrMalformedTokens(String token) {
        assertThatThrownBy(() -> validator.validateAccessToken(token)).isInstanceOf(JwtValidationException.class);
    }

    @Test
    void rejectsUnsignedTokens() {
        String unsigned = Jwts.builder().subject(user.userId()).compact();
        assertThatThrownBy(() -> validator.validateAccessToken(unsigned))
                .isInstanceOf(JwtValidationException.class).hasMessageContaining("none");
    }

    @Test
    void rejectsUnknownKeyId() {
        String token = sign(builder().header().keyId("unknown").and());
        assertThatThrownBy(() -> validator.validateAccessToken(token))
                .isInstanceOf(JwtValidationException.class).hasMessageContaining("Unknown Key ID");
    }

    @Test
    void rejectsSignatureFromAnotherKey() {
        String token = builder().signWith(TestKeys.generate("RSA").getPrivate(), Jwts.SIG.RS256).compact();
        assertThatThrownBy(() -> validator.validateAccessToken(token)).isInstanceOf(JwtValidationException.class);
    }

    @Test
    void acceptsRegisteredRotationKey() {
        var previous = TestKeys.generate("RSA");
        keys.registerVerificationKey("previous", previous.getPublic());
        String token = builder().header().keyId("previous").and()
                .signWith(previous.getPrivate(), Jwts.SIG.RS256).compact();
        assertThat(validator.validateAccessToken(token).userId()).isEqualTo(user.userId());
    }

    @Test
    void rejectsWrongIssuerAndAudience() {
        assertThatThrownBy(() -> validator.validateAccessToken(sign(builder().issuer("other"))))
                .isInstanceOf(JwtValidationException.class);
        assertThatThrownBy(() -> validator.validateAccessToken(sign(builder().audience().clear().add("other").and())))
                .isInstanceOf(JwtValidationException.class);
    }

    @Test
    void requiresTokenIdSubjectAndType() {
        assertThatThrownBy(() -> validator.validateAccessToken(sign(builder().id(null))))
                .isInstanceOf(JwtValidationException.class).hasMessageContaining("jti");
        assertThatThrownBy(() -> validator.validateAccessToken(sign(builder().subject(null))))
                .isInstanceOf(JwtValidationException.class).hasMessageContaining("sub");
        assertThatThrownBy(() -> validator.validateAccessToken(sign(builder().claim("type", null))))
                .isInstanceOf(JwtValidationException.class).hasMessageContaining("token type");
    }

    @Test
    void honorsExpirationAndThirtySecondsOfClockSkew() {
        Instant expiry = Instant.parse("2030-01-01T00:00:00Z");
        String token = sign(builder().expiration(Date.from(expiry)));
        JwtValidator withinSkew = new JwtValidator(keys, blacklist, properties,
                Clock.fixed(expiry.plusSeconds(20), ZoneOffset.UTC));
        JwtValidator beyondSkew = new JwtValidator(keys, blacklist, properties,
                Clock.fixed(expiry.plusSeconds(31), ZoneOffset.UTC));
        assertThat(withinSkew.validateAccessToken(token).userId()).isEqualTo(user.userId());
        assertThatThrownBy(() -> beyondSkew.validateAccessToken(token))
                .isInstanceOf(JwtValidationException.class).hasMessageContaining("expired");
    }

    @Test
    void revokedTokenIsRejectedWithoutRevokingOtherTokens() {
        String revoked = generator.generateAccessToken(user);
        String active = generator.generateAccessToken(user);
        validator.revokeToken(revoked);
        assertThatThrownBy(() -> validator.validateAccessToken(revoked)).isInstanceOf(TokenRevokedException.class);
        assertThat(validator.validateAccessToken(active)).isEqualTo(user);
    }

    @Test
    void banningUserRejectsAccessAndRefreshUntilUnbanned() {
        TokenPair pair = generator.generateTokenPair(user);
        blacklist.banUser(user.userId(), Duration.ofMinutes(1));
        assertThatThrownBy(() -> validator.validateAccessToken(pair.accessToken())).isInstanceOf(TokenRevokedException.class);
        assertThatThrownBy(() -> validator.validateRefreshToken(pair.refreshToken())).isInstanceOf(TokenRevokedException.class);
        blacklist.unbanUser(user.userId());
        assertThat(validator.validateAccessToken(pair.accessToken())).isEqualTo(user);
    }

    @Test
    void revocationStoresOnlyRemainingLifetimeAndIgnoresExpiredTokens() {
        Instant now = Instant.parse("2030-01-01T00:00:00Z");
        TokenBlackList store = mock(TokenBlackList.class);
        JwtValidator fixed = new JwtValidator(keys, store, properties, Clock.fixed(now, ZoneOffset.UTC));
        fixed.revokeToken(sign(builder().expiration(Date.from(now.plusSeconds(120)))));
        ArgumentCaptor<Duration> ttl = ArgumentCaptor.forClass(Duration.class);
        verify(store).add(eq("test-jti"), ttl.capture());
        assertThat(ttl.getValue()).isEqualTo(Duration.ofSeconds(120));
        clearInvocations(store);
        fixed.revokeToken(sign(builder().expiration(Date.from(now.minusSeconds(60)))));
        fixed.revokeToken(null);
        fixed.revokeToken(" ");
        verifyNoInteractions(store);
    }

    @Test
    void revocationRejectsInvalidTokensAndMissingIds() {
        assertThatThrownBy(() -> validator.revokeToken("invalid")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> validator.revokeToken(sign(builder().id(null))))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("jti");
    }

    @ParameterizedTest
    @ValueSource(strings = {"EC", "Ed25519"})
    void supportsOtherSigningAlgorithms(String algorithm) {
        AutoAuthProperties alternateProperties = TestKeys.properties(TestKeys.generate(algorithm));
        JwtKeyProvider alternateKeys = new JwtKeyProvider(alternateProperties);
        JwtGenerator alternateGenerator = new JwtGenerator(alternateKeys, alternateProperties);
        JwtValidator alternateValidator = new JwtValidator(alternateKeys, blacklist, alternateProperties);
        assertThat(alternateValidator.validateAccessToken(alternateGenerator.generateAccessToken(user))).isEqualTo(user);
    }

    private JwtBuilder builder() {
        return Jwts.builder().header().keyId(keys.getKid()).and()
                .issuer(properties.getIssuer()).audience().add(properties.getAudience()).and()
                .id("test-jti").subject(user.userId()).claim("type", "access")
                .expiration(Date.from(Instant.now().plusSeconds(300)));
    }

    private String sign(JwtBuilder builder) {
        return builder.signWith(keys.getPrivateKey(), Jwts.SIG.RS256).compact();
    }
}
