package com.autoauth.support;

import com.autoauth.config.AutoAuthProperties;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;

/** Ephemeral test keys; no production credentials or external files are needed. */
public final class TestKeys {
    public static final KeyPair RSA = generate("RSA");

    private TestKeys() {}

    public static KeyPair generate(String algorithm) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
            if (algorithm.equals("RSA")) {
                generator.initialize(2048);
            } else if (algorithm.equals("EC")) {
                generator.initialize(256);
            }
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException("Cannot generate test keys", e);
        }
    }

    public static String pem(String type, byte[] encoded) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, new byte[]{'\n'}).encodeToString(encoded)
                + "\n-----END " + type + "-----\n";
    }

    public static AutoAuthProperties properties() {
        return properties(RSA);
    }

    public static AutoAuthProperties properties(KeyPair pair) {
        AutoAuthProperties properties = new AutoAuthProperties();
        properties.setPrivateKey(pem("PRIVATE KEY", pair.getPrivate().getEncoded()));
        properties.setPublicKey(pem("PUBLIC KEY", pair.getPublic().getEncoded()));
        return properties;
    }
}
