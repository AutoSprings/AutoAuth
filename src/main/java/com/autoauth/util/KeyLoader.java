package com.autoauth.util;

import org.springframework.core.io.DefaultResourceLoader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

/** Loads RSA PKCS#8 private keys and X.509 SubjectPublicKeyInfo public keys. */
public final class KeyLoader {
    private KeyLoader() {}

    private static byte[] decode(String input) {
        if (input == null || input.isBlank()) throw new IllegalArgumentException("Key must not be blank");
        String content = input.trim();
        try {
            if (content.startsWith("classpath:") || content.startsWith("file:")) {
                try (var stream = new DefaultResourceLoader().getResource(content).getInputStream()) {
                    content = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
                }
            } else if (!content.contains("-----BEGIN") && !content.contains("\n") && content.length() < 260
                    && Files.isRegularFile(Path.of(content))) {
                content = Files.readString(Path.of(content));
            }
            if (content.contains("BEGIN RSA PRIVATE KEY")) {
                throw new IllegalArgumentException("PKCS#1 is unsupported; convert the private key to PKCS#8");
            }
            String encoded = content.lines().map(String::trim)
                    .filter(line -> !line.startsWith("-----")).collect(Collectors.joining());
            return Base64.getDecoder().decode(encoded);
        } catch (Exception exception) {
            throw new IllegalArgumentException("Unable to load key; use RSA PKCS#8 private or X.509 public key material", exception);
        }
    }

    public static PrivateKey loadPrivateKey(String input) {
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decode(input)));
        } catch (Exception exception) {
            throw new IllegalArgumentException("Unable to load RSA PKCS#8 private key", exception);
        }
    }

    public static PublicKey loadPublicKey(String input) {
        try {
            return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decode(input)));
        } catch (Exception exception) {
            throw new IllegalArgumentException("Unable to load RSA X.509 public key", exception);
        }
    }
}
