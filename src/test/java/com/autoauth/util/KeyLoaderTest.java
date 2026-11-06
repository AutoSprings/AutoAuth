package com.autoauth.util;

import com.autoauth.support.TestKeys;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.net.*;
import java.nio.file.*;
import java.util.Base64;
import java.util.jar.*;
import static org.assertj.core.api.Assertions.*;

class KeyLoaderTest {
    @TempDir Path directory;

    @Test
    void loadsRsaPemRawBase64PathsAndUris() throws Exception {
        String privatePem = TestKeys.pem("PRIVATE KEY", TestKeys.RSA.getPrivate().getEncoded());
        String publicPem = TestKeys.pem("PUBLIC KEY", TestKeys.RSA.getPublic().getEncoded());
        assertThat(KeyLoader.loadPrivateKey(privatePem)).isEqualTo(TestKeys.RSA.getPrivate());
        assertThat(KeyLoader.loadPublicKey(publicPem)).isEqualTo(TestKeys.RSA.getPublic());
        assertThat(KeyLoader.loadPublicKey(Base64.getEncoder().encodeToString(TestKeys.RSA.getPublic().getEncoded())))
                .isEqualTo(TestKeys.RSA.getPublic());
        Path file = directory.resolve("private.pem");
        Files.writeString(file, privatePem);
        assertThat(KeyLoader.loadPrivateKey(file.toString())).isEqualTo(TestKeys.RSA.getPrivate());
        assertThat(KeyLoader.loadPrivateKey(file.toUri().toString())).isEqualTo(TestKeys.RSA.getPrivate());
    }

    @Test
    void loadsClasspathResourcesInsideJar() throws Exception {
        Path jar = directory.resolve("keys.jar");
        try (var output = new JarOutputStream(Files.newOutputStream(jar))) {
            output.putNextEntry(new JarEntry("test-public.pem"));
            output.write(TestKeys.pem("PUBLIC KEY", TestKeys.RSA.getPublic().getEncoded())
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8));
            output.closeEntry();
        }
        ClassLoader original = Thread.currentThread().getContextClassLoader();
        try (var loader = new URLClassLoader(new URL[]{jar.toUri().toURL()}, original)) {
            Thread.currentThread().setContextClassLoader(loader);
            assertThat(KeyLoader.loadPublicKey("classpath:test-public.pem")).isEqualTo(TestKeys.RSA.getPublic());
        } finally {
            Thread.currentThread().setContextClassLoader(original);
        }
    }

    @Test
    void rejectsMissingMalformedAndUnsupportedKeys() {
        for (String value : new String[]{null, "", " ", "bad", "YWJj", "classpath:missing.pem",
                "-----BEGIN RSA PRIVATE KEY-----\nYWJj\n-----END RSA PRIVATE KEY-----"}) {
            assertThatThrownBy(() -> KeyLoader.loadPrivateKey(value)).isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> KeyLoader.loadPublicKey(value)).isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> KeyLoader.loadPublicKey(
                TestKeys.pem("PUBLIC KEY", TestKeys.generate("EC").getPublic().getEncoded())))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
