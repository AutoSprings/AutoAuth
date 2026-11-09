package demo;

import com.autoauth.annotation.PublicEndpoint;
import com.autoauth.annotation.RequiresRole;
import com.autoauth.exception.JwtValidationException;
import com.autoauth.jwt.*;
import com.autoauth.model.AutoAuthUser;
import com.autoauth.util.AuthContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;

import java.security.KeyPairGenerator;
import java.util.*;

/** Disposable local demonstration; accounts, credentials, and keys are not production configuration. */
@SpringBootApplication
@RestController
public class DemoApplication {
    private final JwtGenerator generator;
    private final JwtValidator validator;
    private final JwtCookies cookies;
    private final com.autoauth.config.AutoAuthProperties properties;

    public DemoApplication(JwtGenerator generator, JwtValidator validator, JwtCookies cookies,
                           com.autoauth.config.AutoAuthProperties properties) {
        this.generator = generator;
        this.validator = validator;
        this.cookies = cookies;
        this.properties = properties;
    }

    @Bean
    public io.swagger.v3.oas.models.OpenAPI consumerDocumentation() {
        return new io.swagger.v3.oas.models.OpenAPI().info(new io.swagger.v3.oas.models.info.Info()
                .title("AutoAuth cookie example").version("1"));
    }

    public static void main(String[] args) throws Exception {
        var keys = KeyPairGenerator.getInstance("RSA");
        keys.initialize(2048);
        String privateKey = "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder(64, new byte[]{'\n'})
                .encodeToString(keys.generateKeyPair().getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----";
        var app = new SpringApplication(DemoApplication.class);
        app.setDefaultProperties(Map.of("autoauth.private-key", privateKey, "autoauth.cookie-secure", "false",
                "autoauth.swagger-public", "true", "server.address", "127.0.0.1"));
        app.run(args);
    }

    // Demonstration accounts only. Production applications must verify stored password hashes.
    private static AutoAuthUser account(String id) {
        return switch (id) {
            case "alice" -> new AutoAuthUser(id, List.of("USER"), Map.of("tenant", "demo"));
            case "admin" -> new AutoAuthUser(id, List.of("ADMIN"), Map.of("tenant", "demo"));
            default -> null;
        };
    }
    public record Credentials(String username, String password) {}

    @PublicEndpoint @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody Credentials credentials, HttpServletResponse response) {
        var user = credentials.username() == null ? null : account(credentials.username());
        if (user == null || !"demo-only".equals(credentials.password())) return ResponseEntity.status(401).body("Invalid credentials");
        cookies.write(response, generator.generateTokenPair(user));
        return ResponseEntity.ok("Logged in");
    }

    @PublicEndpoint @PostMapping("/refresh")
    public ResponseEntity<String> refresh(HttpServletRequest request, HttpServletResponse response) {
        try {
            String token = null;
            if (request.getCookies() != null) for (var cookie : request.getCookies()) {
                if (properties.getRefreshCookieName().equals(cookie.getName())) {
                    if (token != null) return ResponseEntity.status(401).body("Duplicate refresh cookie");
                    token = cookie.getValue();
                }
            }
            var subject = validator.validateRefreshToken(token);
            // Reload current roles/claims from trusted application data, never from the refresh token.
            var current = account(subject.userId());
            if (current == null) return ResponseEntity.status(401).body("Unknown account");
            // Production applications apply their atomic refresh-session/replay policy here.
            cookies.write(response, generator.generateTokenPair(current));
            return ResponseEntity.ok("Refreshed");
        } catch (JwtValidationException exception) {
            return ResponseEntity.status(401).body("Invalid refresh token");
        }
    }

    @GetMapping("/me") public AutoAuthUser me() { return AuthContext.getCurrentUser().orElseThrow(); }
    @RequiresRole("ADMIN") @GetMapping("/admin") public String admin() { return "Admin access"; }
    @PostMapping("/logout") public String logout(HttpServletResponse response) {
        cookies.clear(response);
        return "Browser cookies cleared";
    }
}
