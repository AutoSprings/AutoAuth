package com.autoauth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import java.util.ArrayList;
import java.util.List;

/**
 * Class to read the .YAML file with configurations
 *
 * Configurations needed are a jwtSecret password to sign and verify JWT keys
 * Allowed origins
 * Endpoints that you don't want to have a JWT token to get to. By default, all Endpoints need a token.
 */

@ConfigurationProperties(prefix = "autoauth")
public class AutoAuthProperties {

    private String privateKey;
    private String publicKey;

    private String cookieName;

    private String jwtSecret;

    private String issuer = "autoauth-default-issuer";
    private String audience = "autoauth-default-audience";

    private long expirationMinutes = 15;
    private long refreshExpirationMinutes = 10080;

    private List<String> allowedOrigins = new ArrayList<>();

    private List<String> publicPaths = new ArrayList<>();

    public String getIssuer() {return issuer;}

    public void setIssuer(String issuer) {this.issuer = issuer;}

    public String getAudience() {return audience;}

    public void setAudience(String audience) {this.audience = audience;}

    public String getJwtSecret() { return jwtSecret; }
    public void setJwtSecret(String jwtSecret) { this.jwtSecret = jwtSecret; }

    public long getExpirationMinutes() { return expirationMinutes; }
    public void setExpirationMinutes(long expirationMinutes) { this.expirationMinutes = expirationMinutes; }

    public List<String> getAllowedOrigins() { return allowedOrigins; }
    public void setAllowedOrigins(List<String> allowedOrigins) { this.allowedOrigins = allowedOrigins; }

    public List<String> getPublicPaths() { return publicPaths; }
    public void setPublicPaths(List<String> publicPaths) { this.publicPaths = publicPaths; }

    public String getCookieName() { return cookieName; }
    public void setCookieName(String cookieName) { this.cookieName = cookieName; }

    public String getPrivateKey() { return privateKey; }
    public void setPrivateKey(String privateKey) { this.privateKey = privateKey; }

    public String getPublicKey() { return publicKey; }
    public void setPublicKey(String publicKey) { this.publicKey = publicKey; }

    public long getRefreshExpirationMinutes() { return refreshExpirationMinutes; }
    public void setRefreshExpirationMinutes(long refreshExpirationMinutes) { this.refreshExpirationMinutes = refreshExpirationMinutes; }

}
