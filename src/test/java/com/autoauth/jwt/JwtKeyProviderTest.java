package com.autoauth.jwt;

import com.autoauth.config.AutoAuthProperties;
import com.autoauth.support.TestKeys;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class JwtKeyProviderTest {
    @Test
    void derivesPublicKeyFromRsaPrivateKey() {
        AutoAuthProperties properties = TestKeys.properties();
        properties.setPublicKey(null);
        JwtKeyProvider keys = new JwtKeyProvider(properties);
        assertThat(keys.getPublicKey()).isEqualTo(TestKeys.RSA.getPublic());
        assertThat(keys.getPrivateKey()).isEqualTo(TestKeys.RSA.getPrivate());
    }

    @Test
    void keyIdIsStableAndVerificationKeysCannotBeModifiedByCaller() {
        JwtKeyProvider keys = new JwtKeyProvider(TestKeys.properties());
        assertThat(keys.getKid()).isEqualTo(new JwtKeyProvider(TestKeys.properties()).getKid());
        assertThat(keys.getPublicKey(keys.getKid())).isEqualTo(keys.getPublicKey());
        assertThat(keys.getPublicKey(null)).isEqualTo(keys.getPublicKey());
        assertThat(keys.getPublicKey(" ")).isEqualTo(keys.getPublicKey());
        assertThat(keys.getPublicKey("unknown")).isNull();
        assertThatThrownBy(() -> keys.getAllVerificationKeys().clear()).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void registersRotationKeysAndIgnoresNullRegistrations() {
        JwtKeyProvider keys = new JwtKeyProvider(TestKeys.properties());
        var previous = TestKeys.generate("RSA").getPublic();
        keys.registerVerificationKey("previous", previous);
        keys.registerVerificationKey(null, previous);
        keys.registerVerificationKey("invalid", null);
        assertThat(keys.getPublicKey("previous")).isEqualTo(previous);
        assertThat(keys.getAllVerificationKeys()).hasSize(2);
    }

    @Test
    void supportsVerificationWithoutPrivateKey() {
        AutoAuthProperties properties = TestKeys.properties();
        properties.setPrivateKey(null);
        JwtKeyProvider keys = new JwtKeyProvider(properties);
        assertThat(keys.getPublicKey()).isEqualTo(TestKeys.RSA.getPublic());
        assertThatThrownBy(keys::getPrivateKey).isInstanceOf(IllegalStateException.class).hasMessageContaining("sign");
    }

    @Test
    void missingKeysFailWhenUsed() {
        JwtKeyProvider keys = new JwtKeyProvider(new AutoAuthProperties());
        assertThat(keys.getAllVerificationKeys()).isEmpty();
        assertThatThrownBy(keys::getPrivateKey).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(keys::getPublicKey).isInstanceOf(IllegalStateException.class);
    }
}
