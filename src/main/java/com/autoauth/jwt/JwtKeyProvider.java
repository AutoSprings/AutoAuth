package com.autoauth.jwt;

import com.autoauth.config.AutoAuthProperties;
import com.autoauth.util.KeyLoader;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/** A fixed RSA key pair, or a public verification key for verifier-only services. */
public class JwtKeyProvider {
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final String kid;

    public JwtKeyProvider(AutoAuthProperties properties) {
        properties.validate();
        try {
            privateKey = hasText(properties.getPrivateKey()) ? KeyLoader.loadPrivateKey(properties.getPrivateKey()) : null;
            PublicKey loaded = hasText(properties.getPublicKey()) ? KeyLoader.loadPublicKey(properties.getPublicKey()) : null;
            if (loaded == null && privateKey instanceof RSAPrivateCrtKey rsa) {
                loaded = KeyFactory.getInstance("RSA").generatePublic(
                        new RSAPublicKeySpec(rsa.getModulus(), rsa.getPublicExponent()));
            }
            if (!(loaded instanceof RSAPublicKey rsa) || rsa.getModulus().bitLength() < 2048) {
                throw new IllegalArgumentException("An RSA verification key of at least 2048 bits is required");
            }
            publicKey = loaded;
            if (privateKey != null) {
                Signature signature = Signature.getInstance("SHA256withRSA");
                byte[] probe = "AutoAuth key-pair validation".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                signature.initSign(privateKey);
                signature.update(probe);
                byte[] signed = signature.sign();
                signature.initVerify(publicKey);
                signature.update(probe);
                if (!signature.verify(signed)) throw new IllegalArgumentException("RSA private/public keys do not match");
            }
            kid = Base64.getUrlEncoder().withoutPadding().encodeToString(
                    MessageDigest.getInstance("SHA-256").digest(publicKey.getEncoded()));
        } catch (IllegalArgumentException exception) {
            throw exception;
        } catch (GeneralSecurityException exception) {
            throw new IllegalArgumentException("Unable to initialize RSA keys", exception);
        }
    }

    private static boolean hasText(String value) { return value != null && !value.isBlank(); }
    public boolean canSign() { return privateKey != null; }
    public PrivateKey getPrivateKey() {
        if (privateKey == null) throw new IllegalStateException("A private key is required to sign tokens");
        return privateKey;
    }
    public PublicKey getPublicKey() { return publicKey; }
    public String getKid() { return kid; }
}
