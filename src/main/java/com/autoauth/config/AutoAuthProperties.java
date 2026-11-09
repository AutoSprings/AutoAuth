package com.autoauth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

/** Settings for access/refresh JWTs, browser cookies, and endpoint security. */
@ConfigurationProperties(prefix = "autoauth")
public class AutoAuthProperties {
    public enum Transport { COOKIE_AND_BEARER, BEARER }

    private String privateKey;
    private String publicKey;
    private String issuer = "autoauth-default-issuer";
    private String audience = "autoauth-default-audience";
    private long expirationMinutes = 15;
    private long refreshExpirationMinutes = 10080;
    private Transport transport = Transport.COOKIE_AND_BEARER;
    private String cookieName = "AUTOAUTH";
    private String refreshCookieName = "AUTOAUTH_REFRESH";
    private boolean cookieSecure = true;
    private String cookieSameSite = "Lax";
    private boolean swaggerPublic = false;
    private int maxTokenLength = 16384;
    /** Maximum UTF-8 bytes per Set-Cookie header value, including name and attributes. */
    private int maxCookieSize = 3800;
    private List<String> allowedOrigins = new ArrayList<>();
    private List<String> publicPaths = new ArrayList<>();

    public boolean isCookieEnabled() { return transport == Transport.COOKIE_AND_BEARER; }

    /** Reject invalid settings before accepting requests. */
    public void validate() {
        if (issuer == null || issuer.isBlank() || audience == null || audience.isBlank()) {
            throw new IllegalArgumentException("autoauth issuer and audience must not be blank");
        }
        validateLifetime(expirationMinutes);
        validateLifetime(refreshExpirationMinutes);
        if (transport == null || maxTokenLength < 256) {
            throw new IllegalArgumentException("autoauth transport and max-token-length are invalid");
        }
        if (maxCookieSize <= 0) {
            throw new IllegalArgumentException("autoauth.max-cookie-size must be positive");
        }
        if (cookieName == null || !cookieName.matches("[A-Za-z0-9_-]+")
                || refreshCookieName == null || !refreshCookieName.matches("[A-Za-z0-9_-]+")
                || cookieName.equals(refreshCookieName) || cookieName.equals("XSRF-TOKEN")
                || refreshCookieName.equals("XSRF-TOKEN")) {
            throw new IllegalArgumentException("autoauth cookie names must be distinct valid names");
        }
        if (!List.of("Lax", "Strict", "None").contains(cookieSameSite)
                || ("None".equals(cookieSameSite) && !cookieSecure)) {
            throw new IllegalArgumentException("autoauth cookie-same-site must be Lax, Strict, or None (with Secure)");
        }
        if (allowedOrigins == null || allowedOrigins.stream().anyMatch(origin ->
                origin == null || origin.isBlank() || origin.contains("*"))) {
            throw new IllegalArgumentException("autoauth allowed-origins must contain explicit origins");
        }
        if (publicPaths == null || publicPaths.stream().anyMatch(path ->
                path == null || !path.startsWith("/"))) {
            throw new IllegalArgumentException("autoauth public-paths must start with /");
        }
    }

    private static void validateLifetime(long minutes) {
        try {
            if (minutes <= 0) throw new ArithmeticException();
            Duration.ofMinutes(minutes).toMillis();
            java.time.Instant.now().plus(Duration.ofMinutes(minutes)).toEpochMilli();
        } catch (ArithmeticException | java.time.DateTimeException exception) {
            throw new IllegalArgumentException("autoauth token lifetimes must be positive and representable", exception);
        }
    }

    public String getPrivateKey() { return privateKey; }
    public void setPrivateKey(String value) { privateKey = value; }
    public String getPublicKey() { return publicKey; }
    public void setPublicKey(String value) { publicKey = value; }
    public String getIssuer() { return issuer; }
    public void setIssuer(String value) { issuer = value; }
    public String getAudience() { return audience; }
    public void setAudience(String value) { audience = value; }
    public long getExpirationMinutes() { return expirationMinutes; }
    public void setExpirationMinutes(long value) { expirationMinutes = value; }
    public long getRefreshExpirationMinutes() { return refreshExpirationMinutes; }
    public void setRefreshExpirationMinutes(long value) { refreshExpirationMinutes = value; }
    public Transport getTransport() { return transport; }
    public void setTransport(Transport value) { transport = value; }
    public String getCookieName() { return cookieName; }
    public void setCookieName(String value) { cookieName = value; }
    public String getRefreshCookieName() { return refreshCookieName; }
    public void setRefreshCookieName(String value) { refreshCookieName = value; }
    public boolean isCookieSecure() { return cookieSecure; }
    public void setCookieSecure(boolean value) { cookieSecure = value; }
    public String getCookieSameSite() { return cookieSameSite; }
    public void setCookieSameSite(String value) { cookieSameSite = value; }
    public boolean isSwaggerPublic() { return swaggerPublic; }
    public void setSwaggerPublic(boolean value) { swaggerPublic = value; }
    public int getMaxTokenLength() { return maxTokenLength; }
    public void setMaxTokenLength(int value) { maxTokenLength = value; }
    /** @return maximum UTF-8 bytes per complete Set-Cookie header value */
    public int getMaxCookieSize() { return maxCookieSize; }
    /** @param value positive byte budget for each complete Set-Cookie header value */
    public void setMaxCookieSize(int value) { maxCookieSize = value; }
    public List<String> getAllowedOrigins() { return allowedOrigins; }
    public void setAllowedOrigins(List<String> value) { allowedOrigins = value; }
    public List<String> getPublicPaths() { return publicPaths; }
    public void setPublicPaths(List<String> value) { publicPaths = value; }
}
