package com.autoauth.controller;

import com.autoauth.config.AutoAuthProperties;
import com.autoauth.jwt.JwtKeyProvider;
import com.autoauth.support.TestKeys;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class JwksControllerTest {
    @Test
    @SuppressWarnings("unchecked")
    void exposesRsaParametersAndCacheHeadersWithoutPrivateKeyMaterial() {
        JwtKeyProvider keys = new JwtKeyProvider(TestKeys.properties());
        var response = new JwksController(keys).getJwks();
        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getHeaders().getCacheControl()).contains("max-age=86400", "public");
        List<Map<String, Object>> jwks = (List<Map<String, Object>>) response.getBody().get("keys");
        assertThat(jwks).hasSize(1);
        Map<String, Object> jwk = jwks.getFirst();
        assertThat(jwk).containsEntry("kty", "RSA").containsEntry("alg", "RS256")
                .containsEntry("use", "sig").containsEntry("kid", keys.getKid())
                .containsOnlyKeys("kty", "alg", "use", "kid", "n", "e");
        RSAPublicKey publicKey = (RSAPublicKey) keys.getPublicKey();
        byte[] modulus = Base64.getUrlDecoder().decode((String) jwk.get("n"));
        assertThat(modulus[0]).isNotZero();
        assertThat(new BigInteger(1, modulus)).isEqualTo(publicKey.getModulus());
        assertThat(new BigInteger(1, Base64.getUrlDecoder().decode((String) jwk.get("e"))))
                .isEqualTo(publicKey.getPublicExponent());
        assertThat((String) jwk.get("n")).doesNotContain("=", "+", "/");
    }

    @Test
    void missingPublicKeyReturnsEmptyUncachedKeySet() {
        var response = new JwksController(new JwtKeyProvider(new AutoAuthProperties())).getJwks();
        assertThat(response.getBody()).containsEntry("keys", List.of());
        assertThat(response.getHeaders().getCacheControl()).isEqualTo("no-cache");
    }
}
