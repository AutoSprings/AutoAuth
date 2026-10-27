package com.autoauth.util;

import com.autoauth.support.TestKeys;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

import static org.assertj.core.api.Assertions.*;

class KeyLoaderTest {
    @TempDir Path directory;

    @ParameterizedTest
    @ValueSource(strings = {"RSA", "EC", "Ed25519"})
    void loadsPrivateAndPublicPemKeys(String algorithm) {
        var pair = algorithm.equals("RSA") ? TestKeys.RSA : TestKeys.generate(algorithm);
        assertThat(KeyLoader.loadPrivateKey(TestKeys.pem("PRIVATE KEY", pair.getPrivate().getEncoded())))
                .isEqualTo(pair.getPrivate());
        assertThat(KeyLoader.loadPublicKey(TestKeys.pem("PUBLIC KEY", pair.getPublic().getEncoded())))
                .isEqualTo(pair.getPublic());
    }

    @Test
    void loadsRawBase64AndCachesParsedKeys() {
        String privateKey = Base64.getEncoder().encodeToString(TestKeys.RSA.getPrivate().getEncoded());
        String publicKey = Base64.getEncoder().encodeToString(TestKeys.RSA.getPublic().getEncoded());
        assertThat(KeyLoader.loadPrivateKey(privateKey)).isEqualTo(TestKeys.RSA.getPrivate());
        assertThat(KeyLoader.loadPublicKey(publicKey)).isEqualTo(TestKeys.RSA.getPublic());
        assertThat(KeyLoader.loadPrivateKey(privateKey)).isSameAs(KeyLoader.loadPrivateKey(privateKey));
        assertThat(KeyLoader.loadPublicKey(publicKey)).isSameAs(KeyLoader.loadPublicKey(publicKey));
    }

    @Test
    void loadsKeysFromPathsAndFileUris() throws Exception {
        Path privateFile = directory.resolve("private.pem");
        Path publicFile = directory.resolve("public.pem");
        Files.writeString(privateFile, TestKeys.pem("PRIVATE KEY", TestKeys.RSA.getPrivate().getEncoded()));
        Files.writeString(publicFile, TestKeys.pem("PUBLIC KEY", TestKeys.RSA.getPublic().getEncoded()));
        assertThat(KeyLoader.loadPrivateKey(privateFile.toString())).isEqualTo(TestKeys.RSA.getPrivate());
        assertThat(KeyLoader.loadPublicKey(publicFile.toUri().toString())).isEqualTo(TestKeys.RSA.getPublic());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "not a key", "YWJj"})
    void rejectsMissingOrMalformedKeys(String value) {
        assertThatThrownBy(() -> KeyLoader.loadPrivateKey(value)).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> KeyLoader.loadPublicKey(value)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void reportsMissingResource() {
        assertThatThrownBy(() -> KeyLoader.loadPublicKey("classpath:missing-test-key.pem"))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("Failed to read key file");
    }
}
