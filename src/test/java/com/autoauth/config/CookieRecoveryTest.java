package com.autoauth.config;

import com.autoauth.annotation.PublicEndpoint;
import com.autoauth.exception.JwtValidationException;
import com.autoauth.jwt.*;
import com.autoauth.model.AutoAuthUser;
import com.autoauth.model.TokenPair;
import com.autoauth.support.TestKeys;
import com.autoauth.util.AuthContext;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.*;

import java.time.*;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Application-owned demo handlers exercised through the full JWT and CSRF chain. */
@SpringBootTest(classes = CookieRecoveryTest.App.class, properties = {
        "autoauth.cookie-secure=false", "autoauth.swagger-public=true", "autoauth.public-paths[0]=/recovery/manual"})
@AutoConfigureMockMvc
class CookieRecoveryTest {
    private static final Instant NOW = Instant.parse("2030-01-01T00:00:00Z");
    @Autowired MockMvc mvc;
    @Autowired JwtGenerator generator;
    @Autowired JwtValidator validator;
    @Autowired JwtKeyProvider keys;
    @Autowired AutoAuthProperties properties;

    @DynamicPropertySource
    static void keys(DynamicPropertyRegistry registry) {
        registry.add("autoauth.private-key", () -> TestKeys.properties().getPrivateKey());
    }

    @Test
    void staleAccessCookieCanBootstrapRefreshAndAuthenticateWithReplacementWithoutClearingCookies() throws Exception {
        TokenPair stale = stalePair();
        Cookie access = access(stale.accessToken());
        Cookie refresh = refresh(stale.refreshToken());
        mvc.perform(get("/recovery/private").cookie(access, refresh)).andExpect(status().isUnauthorized());
        Cookie csrf = csrf(access, refresh);
        var renewed = mvc.perform(post("/recovery/refresh").cookie(access, refresh, csrf)
                        .header("X-XSRF-TOKEN", csrf.getValue()))
                .andExpect(status().isOk()).andExpect(content().string("anonymous")).andReturn().getResponse();
        Cookie newAccess = renewed.getCookie(properties.getCookieName());
        Cookie newRefresh = renewed.getCookie(properties.getRefreshCookieName());
        assertThat(newAccess).isNotNull();
        assertThat(newRefresh).isNotNull();
        // The application reloads current roles/claims instead of copying the stale token's ADMIN role.
        assertThat(validator.validateAccessToken(newAccess.getValue()).roles()).containsExactly("USER");
        assertThat(validator.validateAccessToken(newAccess.getValue()).customClaims()).containsEntry("tenant", "current");
        mvc.perform(get("/recovery/private").cookie(newAccess, newRefresh, csrf))
                .andExpect(status().isOk()).andExpect(content().string("alice:USER"));
    }

    @Test
    void expiredCookieDoesNotAuthenticatePublicHandlersAndLoginStillValidatesCredentials() throws Exception {
        Cookie stale = access(stalePair().accessToken());
        Cookie csrf = csrf(stale);
        mvc.perform(get("/recovery/public").cookie(stale)).andExpect(status().isOk())
                .andExpect(content().string("anonymous"));
        mvc.perform(post("/recovery/login").param("user", "alice").param("password", "wrong")
                        .cookie(stale, csrf).header("X-XSRF-TOKEN", csrf.getValue()))
                .andExpect(status().isUnauthorized()).andExpect(content().string("invalid credentials"));
        mvc.perform(post("/recovery/login").param("user", "alice").param("password", "demo-only")
                        .cookie(stale, csrf).header("X-XSRF-TOKEN", csrf.getValue()))
                .andExpect(status().isOk()).andExpect(content().string("anonymous"))
                .andExpect(cookie().exists(properties.getCookieName()));
    }

    @Test
    void unsafePublicRecoveryRoutesStillRequireRealCsrfProtection() throws Exception {
        TokenPair pair = stalePair();
        Cookie access = access(pair.accessToken());
        Cookie refresh = refresh(pair.refreshToken());
        Cookie csrf = csrf(access, refresh);
        mvc.perform(post("/recovery/refresh").cookie(access, refresh)).andExpect(status().isForbidden());
        mvc.perform(post("/recovery/refresh").cookie(access, refresh, csrf).header("X-XSRF-TOKEN", "wrong"))
                .andExpect(status().isForbidden());
        mvc.perform(post("/recovery/login").param("user", "alice").param("password", "demo-only").cookie(access))
                .andExpect(status().isForbidden());
    }

    @Test
    void recoveryUsesTheSamePublicMatcherIncludingHttpMethodAndMappingConditions() throws Exception {
        Cookie stale = access(stalePair().accessToken());
        Cookie csrf = csrf(stale);
        mvc.perform(get("/recovery/shared").cookie(stale)).andExpect(status().isOk());
        mvc.perform(post("/recovery/shared").cookie(stale, csrf).header("X-XSRF-TOKEN", csrf.getValue()))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/recovery/choice").param("public", "true").cookie(stale)).andExpect(status().isOk());
        mvc.perform(get("/recovery/choice").cookie(stale)).andExpect(status().isUnauthorized());
        mvc.perform(get("/recovery/manual").cookie(stale)).andExpect(status().isOk());
        mvc.perform(get("/recovery/unknown").cookie(stale)).andExpect(status().isUnauthorized());
        mvc.perform(post("/autoauth/csrf").cookie(stale, csrf).header("X-XSRF-TOKEN", csrf.getValue()))
                .andExpect(status().isUnauthorized());
        mvc.perform(get("/v3/api-docs").cookie(stale)).andExpect(status().isOk());
    }

    @Test
    void applicationRejectsInvalidRefreshTokensEvenWhenStaleAccessCookieCanBeIgnored() throws Exception {
        Cookie stale = access(stalePair().accessToken());
        Cookie csrf = csrf(stale);
        String expiredRefresh = new JwtGenerator(keys, properties,
                Clock.fixed(NOW.minus(Duration.ofDays(8)), ZoneOffset.UTC))
                .generateRefreshToken(new AutoAuthUser("alice", null, null));
        for (String token : List.of("malformed", expiredRefresh,
                generator.generateAccessToken(new AutoAuthUser("alice", null, null)),
                generator.generateRefreshToken(new AutoAuthUser("unknown-account", null, null)))) {
            mvc.perform(post("/recovery/refresh").cookie(stale, refresh(token), csrf)
                            .header("X-XSRF-TOKEN", csrf.getValue()))
                    .andExpect(status().isUnauthorized()).andExpect(content().string("invalid refresh"))
                    .andExpect(cookie().doesNotExist(properties.getCookieName()));
        }
        mvc.perform(post("/recovery/refresh").cookie(stale, csrf).header("X-XSRF-TOKEN", csrf.getValue()))
                .andExpect(status().isUnauthorized()).andExpect(content().string("invalid refresh"));
    }

    @Test
    void invalidBearerHeadersNeverFallBackToCookiesOrAcquirePublicCookieRecovery() throws Exception {
        TokenPair stale = stalePair();
        String validAccess = generator.generateAccessToken(new AutoAuthUser("alice", List.of("USER"), null));
        for (String header : List.of("Bearer", "Bearer ", "BearerX value", "Bearer  invalid", "Bearer invalid",
                "Bearer " + stale.accessToken(), "Bearer " + stale.refreshToken())) {
            mvc.perform(get("/recovery/private").header("Authorization", header).cookie(access(validAccess)))
                    .andExpect(status().isUnauthorized()).andExpect(header().string("WWW-Authenticate", "Bearer"));
            mvc.perform(get("/autoauth/csrf").header("Authorization", header)
                            .cookie(access(stale.accessToken()), refresh(stale.refreshToken())))
                    .andExpect(status().isUnauthorized());
        }
    }

    @Test
    void validBearerOverridesExpiredMalformedAndDuplicateAccessCookies() throws Exception {
        String valid = generator.generateAccessToken(new AutoAuthUser("alice", List.of("USER"), null));
        for (String value : List.of(stalePair().accessToken(), "invalid")) {
            mvc.perform(get("/recovery/private").header("Authorization", "bEaReR " + valid)
                            .cookie(access(value), access("duplicate")))
                    .andExpect(status().isOk()).andExpect(content().string("alice:USER"));
        }
    }

    @Test
    void invalidAccessCookiesRemainRejectedOnPublicRoutesEvenWithValidRefreshCookie() throws Exception {
        TokenPair stale = stalePair();
        String wrongIssuer = Jwts.builder().issuer("other").audience().add(properties.getAudience()).and()
                .subject("alice").id("id").claim("type", "access").expiration(Date.from(NOW.minusSeconds(60)))
                .signWith(keys.getPrivateKey(), Jwts.SIG.RS256).compact();
        String wrongSignature = new JwtGenerator(new JwtKeyProvider(TestKeys.properties(TestKeys.generate("RSA"))),
                properties, Clock.fixed(NOW.minus(Duration.ofMinutes(16)), ZoneOffset.UTC))
                .generateAccessToken(new AutoAuthUser("alice", null, null));
        String expiredRefresh = new JwtGenerator(keys, properties,
                Clock.fixed(NOW.minus(Duration.ofDays(8)), ZoneOffset.UTC))
                .generateRefreshToken(new AutoAuthUser("alice", null, null));
        for (String value : List.of("invalid", wrongIssuer, wrongSignature, stale.refreshToken(), expiredRefresh)) {
            mvc.perform(get("/autoauth/csrf").cookie(access(value), refresh(stale.refreshToken())))
                    .andExpect(status().isUnauthorized());
        }
        mvc.perform(get("/autoauth/csrf").cookie(access(stale.accessToken()), access(stale.accessToken())))
                .andExpect(status().isUnauthorized());
    }

    private TokenPair stalePair() {
        return new JwtGenerator(keys, properties, Clock.fixed(NOW.minus(Duration.ofMinutes(16)), ZoneOffset.UTC))
                .generateTokenPair(new AutoAuthUser("alice", List.of("ADMIN"), Map.of("legacy", true)));
    }

    private Cookie access(String token) { return new Cookie(properties.getCookieName(), token); }
    private Cookie refresh(String token) { return new Cookie(properties.getRefreshCookieName(), token); }
    private Cookie csrf(Cookie... cookies) throws Exception {
        Cookie token = mvc.perform(get("/autoauth/csrf").cookie(cookies)).andExpect(status().isOk())
                .andReturn().getResponse().getCookie("XSRF-TOKEN");
        assertThat(token).isNotNull();
        return token;
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @Import(Routes.class)
    static class App {
        @Bean Clock clock() { return Clock.fixed(NOW, ZoneOffset.UTC); }
    }

    @RestController
    public static class Routes {
        private final JwtGenerator generator;
        private final JwtValidator validator;
        private final JwtCookies cookies;
        Routes(JwtGenerator generator, JwtValidator validator, JwtCookies cookies) {
            this.generator = generator;
            this.validator = validator;
            this.cookies = cookies;
        }
        @PublicEndpoint @PostMapping("/recovery/refresh")
        public ResponseEntity<String> refresh(@CookieValue(name = "AUTOAUTH_REFRESH", required = false) String token,
                                               HttpServletResponse response) {
            try {
                AutoAuthUser subject = validator.validateRefreshToken(token);
                if (!subject.userId().equals("alice")) return ResponseEntity.status(401).body("invalid refresh");
                issue(response);
                return ResponseEntity.ok(AuthContext.getCurrentUserId().orElse("anonymous"));
            } catch (JwtValidationException exception) {
                return ResponseEntity.status(401).body("invalid refresh");
            }
        }
        @PublicEndpoint @PostMapping("/recovery/login")
        public ResponseEntity<String> login(@RequestParam("user") String user, @RequestParam("password") String password,
                                             HttpServletResponse response) {
            if (!user.equals("alice") || !password.equals("demo-only")) return ResponseEntity.status(401).body("invalid credentials");
            issue(response);
            return ResponseEntity.ok(AuthContext.getCurrentUserId().orElse("anonymous"));
        }
        private void issue(HttpServletResponse response) {
            cookies.write(response, generator.generateTokenPair(new AutoAuthUser("alice", List.of("USER"), Map.of("tenant", "current"))));
        }
        @PublicEndpoint @GetMapping({"/recovery/public", "/recovery/shared"})
        public String open() { return AuthContext.getCurrentUserId().orElse("anonymous"); }
        @PostMapping("/recovery/shared") public String protectedPost() { return "protected"; }
        @PublicEndpoint @GetMapping(path = "/recovery/choice", params = "public")
        public String publicChoice() { return "public"; }
        @GetMapping(path = "/recovery/choice", params = "!public") public String privateChoice() { return "protected"; }
        @GetMapping("/recovery/manual") public String manual() { return "configured public"; }
        @GetMapping("/recovery/private") public String privateRoute() {
            return AuthContext.getCurrentUserId().orElseThrow() + ":" + String.join(",", AuthContext.getCurrentUserRoles().orElseThrow());
        }
    }
}
