package com.autoauth.config;

import com.autoauth.aop.RoleAspect;
import com.autoauth.annotation.PublicEndpoint;
import com.autoauth.annotation.RequiresRole;
import com.autoauth.blacklist.CafeTokenBlackList;
import com.autoauth.blacklist.TokenBlackList;
import com.autoauth.controller.JwksController;
import com.autoauth.jwt.JwtGenerator;
import com.autoauth.jwt.JwtKeyProvider;
import com.autoauth.jwt.JwtValidator;
import com.autoauth.model.AutoAuthUser;
import com.autoauth.support.TestKeys;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class AutoAuthConfigurationTest {
    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AutoAuthAutoConfiguration.class))
            .withUserConfiguration(WebConfig.class);

    @Test
    void createsDefaultBeansAndBindsDefaultProperties() {
        runner.run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(JwtKeyProvider.class)
                    .hasSingleBean(JwtGenerator.class).hasSingleBean(JwtValidator.class)
                    .hasSingleBean(RoleAspect.class).hasSingleBean(SecurityFilterChain.class)
                    .hasSingleBean(Clock.class);
            assertThat(context.getBean(TokenBlackList.class)).isInstanceOf(CafeTokenBlackList.class);
            assertThat(context).doesNotHaveBean(JwksController.class);
            AutoAuthProperties properties = context.getBean(AutoAuthProperties.class);
            assertThat(properties.getExpirationMinutes()).isEqualTo(15);
            assertThat(properties.getRefreshExpirationMinutes()).isEqualTo(10080);
            assertThat(properties.getIssuer()).isEqualTo("autoauth-default-issuer");
            assertThat(properties.getAudience()).isEqualTo("autoauth-default-audience");
            assertThat(properties.getPublicPaths()).isEmpty();
            assertThat(properties.getAllowedOrigins()).isEmpty();
            assertThat(context.getBean(Clock.class).getZone()).isEqualTo(ZoneOffset.UTC);
            assertThatThrownBy(() -> Class.forName("com.autolimit.config.AutoLimitAutoConfiguration"))
                    .isInstanceOf(ClassNotFoundException.class);
            assertThat(context.getBean(SecurityFilterChain.class).getFilters())
                    .allMatch(filter -> !filter.getClass().getSimpleName().equals("IpRateLimitFilter"));
        });
    }

    @Test
    void respectsApplicationProvidedBeans() {
        TokenBlackList blacklist = new CafeTokenBlackList();
        Clock clock = Clock.fixed(Instant.parse("2030-01-01T00:00:00Z"), ZoneOffset.UTC);
        OpenAPI openAPI = new OpenAPI();
        runner.withBean(TokenBlackList.class, () -> blacklist).withBean(Clock.class, () -> clock)
                .withBean(OpenAPI.class, () -> openAPI)
                .run(context -> {
                    assertThat(context).hasNotFailed().hasSingleBean(TokenBlackList.class)
                            .hasSingleBean(Clock.class).hasSingleBean(OpenAPI.class);
                    assertThat(context.getBean(TokenBlackList.class)).isSameAs(blacklist);
                    assertThat(context.getBean(Clock.class)).isSameAs(clock);
                    assertThat(context.getBean(OpenAPI.class)).isSameAs(openAPI);
                });
    }

    @Test
    void bindsCustomPropertiesAndProvidesJwksAndSwaggerConfiguration() {
        withKeys().withPropertyValues("autoauth.expiration-minutes=7", "autoauth.refresh-expiration-minutes=90",
                "autoauth.issuer=test-issuer", "autoauth.audience=test-audience", "autoauth.cookie-name=session-token",
                "autoauth.allowed-origins[0]=https://example.test", "autoauth.public-paths[0]=/api/configured")
                .run(context -> {
                    assertThat(context).hasNotFailed().hasSingleBean(JwksController.class).hasSingleBean(OpenAPI.class);
                    AutoAuthProperties properties = context.getBean(AutoAuthProperties.class);
                    assertThat(properties.getExpirationMinutes()).isEqualTo(7);
                    assertThat(properties.getRefreshExpirationMinutes()).isEqualTo(90);
                    assertThat(properties.getIssuer()).isEqualTo("test-issuer");
                    assertThat(properties.getAudience()).isEqualTo("test-audience");
                    assertThat(properties.getCookieName()).isEqualTo("session-token");
                    assertThat(properties.getAllowedOrigins()).containsExactly("https://example.test");
                    assertThat(properties.getPublicPaths()).containsExactly("/api/configured");
                    OpenAPI openAPI = context.getBean(OpenAPI.class);
                    assertThat(openAPI.getSecurity().getFirst()).containsKey("JWT-Bearer");
                    var scheme = openAPI.getComponents().getSecuritySchemes().get("JWT-Bearer");
                    assertThat(scheme.getType()).isEqualTo(SecurityScheme.Type.OAUTH2);
                    assertThat(scheme.getFlows().getPassword().getTokenUrl()).isEqualTo("/api/login");
                });
    }

    @Test
    void publicAnnotationsConfiguredPathsAndJwksAllowAnonymousRequests() {
        withKeys().withPropertyValues("autoauth.public-paths[0]=/api/configured").run(context -> {
            MockMvc mvc = mockMvc(context);
            mvc.perform(get("/api/public")).andExpect(status().isOk());
            mvc.perform(get("/public/status")).andExpect(status().isOk());
            mvc.perform(get("/api/configured")).andExpect(status().isOk());
            mvc.perform(get("/.well-known/jwks.json")).andExpect(status().isOk())
                    .andExpect(jsonPath("$.keys[0].kid").value(context.getBean(JwtKeyProvider.class).getKid()));
            mvc.perform(get("/api/private")).andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.error").value("Unauthorized"));
        });
    }

    @Test
    void validTokensAuthenticateStatelessRequestsAndRoleAnnotationsProtectEndpoints() {
        withKeys().run(context -> {
            MockMvc mvc = mockMvc(context);
            JwtGenerator generator = context.getBean(JwtGenerator.class);
            String user = generator.generateAccessToken(new AutoAuthUser("alice", List.of("USER"), null));
            String admin = generator.generateAccessToken(new AutoAuthUser("admin", List.of("ADMIN"), null));
            var result = mvc.perform(get("/api/private").header("Authorization", "Bearer " + user))
                    .andExpect(status().isOk()).andExpect(content().string("private")).andReturn();
            assertThat(result.getRequest().getSession(false)).isNull();
            mvc.perform(post("/api/private").header("Authorization", "Bearer " + user))
                    .andExpect(status().isOk());
            mvc.perform(get("/api/admin").header("Authorization", "Bearer " + user))
                    .andExpect(status().isForbidden()).andExpect(jsonPath("$.error").value("Forbidden"));
            mvc.perform(get("/api/admin").header("Authorization", "Bearer " + admin)).andExpect(status().isOk());
            mvc.perform(get("/api/private")).andExpect(status().isUnauthorized());
        });
    }

    @Test
    void invalidAndRevokedTokensReturn401AndDoNotBreakPublicEndpoints() {
        withKeys().run(context -> {
            MockMvc mvc = mockMvc(context);
            mvc.perform(get("/api/private").header("Authorization", "Bearer invalid"))
                    .andExpect(status().isUnauthorized());
            mvc.perform(get("/api/public").header("Authorization", "Bearer invalid")).andExpect(status().isOk());
            String token = context.getBean(JwtGenerator.class).generateAccessToken(new AutoAuthUser("alice", null, null));
            context.getBean(JwtValidator.class).revokeToken(token);
            mvc.perform(get("/api/private").header("Authorization", "Bearer " + token))
                    .andExpect(status().isUnauthorized());
        });
    }

    @Test
    void corsPreflightAllowsConfiguredOriginAndRejectsOtherOrigins() {
        withKeys().withPropertyValues("autoauth.allowed-origins[0]=https://example.test").run(context -> {
            MockMvc mvc = mockMvc(context);
            mvc.perform(options("/api/private").header("Origin", "https://example.test")
                            .header("Access-Control-Request-Method", "POST"))
                    .andExpect(status().isOk()).andExpect(header().string("Access-Control-Allow-Origin", "https://example.test"))
                    .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
            mvc.perform(options("/api/private").header("Origin", "https://other.test")
                            .header("Access-Control-Request-Method", "POST"))
                    .andExpect(status().isForbidden());
        });
    }

    private WebApplicationContextRunner withKeys() {
        AutoAuthProperties properties = TestKeys.properties();
        return runner.withPropertyValues("autoauth.private-key=" + properties.getPrivateKey(),
                "autoauth.public-key=" + properties.getPublicKey());
    }

    private MockMvc mockMvc(WebApplicationContext context) {
        return MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    @Import({Routes.class, PublicRoutes.class})
    static class WebConfig {}

    @RestController
    @RequestMapping("/api")
    public static class Routes {
        @PublicEndpoint @GetMapping("/public") public String open() { return "public"; }
        @GetMapping("/configured") public String configured() { return "configured"; }
        @GetMapping("/private") public String secured() { return "private"; }
        @PostMapping("/private") public String post() { return "posted"; }
        @RequiresRole("ADMIN") @GetMapping("/admin") public String admin() { return "admin"; }
    }

    @PublicEndpoint @RestController @RequestMapping("/public")
    public static class PublicRoutes {
        @GetMapping("/status") public String status() { return "ok"; }
    }
}
