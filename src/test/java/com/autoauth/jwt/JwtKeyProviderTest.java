package com.autoauth.jwt;

import com.autoauth.config.AutoAuthProperties;
import com.autoauth.support.TestKeys;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

class JwtKeyProviderTest {
    @Test
    void derivesRsaPublicKeyAndUsesStableKeyId() {
        var properties = TestKeys.properties();
        properties.setPublicKey(null);
        var keys = new JwtKeyProvider(properties);
        assertThat(keys.getPublicKey()).isEqualTo(TestKeys.RSA.getPublic());
        assertThat(keys.getPrivateKey()).isEqualTo(TestKeys.RSA.getPrivate());
        assertThat(keys.getKid()).isEqualTo(new JwtKeyProvider(properties).getKid());
    }
    @Test
    void verifierDoesNotRequireSigningKey() {
        var properties = TestKeys.properties();
        properties.setPrivateKey(null);
        var keys = new JwtKeyProvider(properties);
        assertThat(keys.canSign()).isFalse();
        assertThatThrownBy(keys::getPrivateKey).isInstanceOf(IllegalStateException.class);
    }
    @Test
    void rejectsMissingMismatchedWeakOrNonRsaKeys() throws Exception {
        assertThatThrownBy(() -> new JwtKeyProvider(new AutoAuthProperties())).isInstanceOf(IllegalArgumentException.class);
        var properties = TestKeys.properties();
        properties.setPublicKey(TestKeys.pem("PUBLIC KEY", TestKeys.generate("RSA").getPublic().getEncoded()));
        assertThatThrownBy(() -> new JwtKeyProvider(properties)).isInstanceOf(IllegalArgumentException.class);
        var weak = java.security.KeyPairGenerator.getInstance("RSA");
        weak.initialize(1024);
        assertThatThrownBy(() -> new JwtKeyProvider(TestKeys.properties(weak.generateKeyPair())))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new JwtKeyProvider(TestKeys.properties(TestKeys.generate("EC"))))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
