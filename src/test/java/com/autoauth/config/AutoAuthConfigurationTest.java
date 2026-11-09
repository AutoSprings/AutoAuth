package com.autoauth.config;

import com.autoauth.annotation.*;
import com.autoauth.jwt.*;
import com.autoauth.model.*;
import com.autoauth.support.TestKeys;
import com.autoauth.util.AuthContext;
import com.autoauth.util.EndpointScanner;
import com.autoauth.filter.JwtAuthenticationFilter;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.security.SecurityScheme;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springdoc.core.customizers.OperationCustomizer;

import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.context.annotation.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.core.annotation.Order;
import org.springframework.mock.web.MockHttpServletRequest;
import jakarta.servlet.DispatcherType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import java.util.List;
import static org.assertj.core.api.Assertions.*;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class AutoAuthConfigurationTest {
    private final WebApplicationContextRunner runner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AutoAuthAutoConfiguration.class))
            .withUserConfiguration(WebConfig.class);

    @Test
    void autoConfigurationRejectsUnprotectableRoleHandlers() {
        withKeys().withBean(UnprotectableRoutes.class).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasStackTraceContaining("Cannot enforce @RequiresRole")
                    .hasStackTraceContaining("UnprotectableRoutes.admin").hasStackTraceContaining("final");
        });
    }

    @RestController
    public static class UnprotectableRoutes {
        @RequiresRole("ADMIN") @GetMapping("/unprotectable")
        public final String admin() { return "admin"; }
    }

    @Test
    void defaultCookieAndBearerBeansAndSwaggerAreConfigured() {
        withKeys().run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(JwtGenerator.class).hasSingleBean(JwtValidator.class)
                    .hasSingleBean(JwtCookies.class).hasSingleBean(SecurityFilterChain.class);
            var scheme = context.getBean(OpenAPI.class).getComponents().getSecuritySchemes().get("JWT-Bearer");
            assertThat(scheme.getType()).isEqualTo(SecurityScheme.Type.HTTP);
            assertThat(scheme.getScheme()).isEqualTo("bearer");
            assertThat(scheme.getFlows()).isNull();
            assertThat(context.getBean(OpenAPI.class).getComponents().getSecuritySchemes()).containsKey("JWT-Cookie");
            for (String removed : List.of("com.autoauth.blacklist.TokenBlackList", "com.autoauth.controller.JwksController",
                    "org.springframework.data.redis.core.StringRedisTemplate", "com.github.benmanes.caffeine.cache.Caffeine")) {
                assertThatThrownBy(() -> Class.forName(removed)).isInstanceOf(ClassNotFoundException.class);
            }
        });
    }

    @Test
    void publicMappingsPreserveHttpMethodsAndNeverExposeOtherControllers() {
        withKeys().withPropertyValues("autoauth.transport=BEARER", "autoauth.public-paths[0]=/api/configured").run(context -> {
            MockMvc mvc = mvc(context);
            mvc.perform(get("/api/public")).andExpect(status().isOk());
            mvc.perform(post("/api/public")).andExpect(status().isUnauthorized());
            mvc.perform(get("/public/status")).andExpect(status().isOk());
            mvc.perform(get("/public/private")).andExpect(status().isUnauthorized());
            mvc.perform(get("/health")).andExpect(status().isOk());
            mvc.perform(get("/api/private")).andExpect(status().isUnauthorized());
            mvc.perform(get("/api/configured")).andExpect(status().isOk());
            mvc.perform(post("/api/configured")).andExpect(status().isOk());
            mvc.perform(get("/api/choice").param("public", "true")).andExpect(status().isOk());
            mvc.perform(get("/api/choice")).andExpect(status().isUnauthorized());
        });
    }

    @Test
    void redispatchMatchingReplacesTheOriginalHandlersCachedPath() {
        withKeys().run(context -> {
            var scanner = new EndpointScanner(context);
            for (DispatcherType dispatch : List.of(DispatcherType.FORWARD, DispatcherType.ERROR, DispatcherType.ASYNC)) {
                var request = new MockHttpServletRequest("GET", "/app/api/public");
                request.setContextPath("/app");
                assertThat(scanner.matches(request)).isTrue();
                request.setDispatcherType(dispatch);
                request.setRequestURI("/app/api/private");
                assertThat(scanner.matches(request)).as("%s must match the target", dispatch).isFalse();
                request.setRequestURI("/app/api/public");
                assertThat(scanner.matches(request)).isTrue();
            }
        });
    }

    @Test
    void multipleApplicationChainsReplaceTheDefaultAndOwnAllRoutePermissions() {
        withKeys().withPropertyValues("autoauth.transport=BEARER").withUserConfiguration(MultipleChains.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBeansOfType(SecurityFilterChain.class)).hasSize(2).doesNotContainKey("securityFilterChain");
            var mvc = mvc(context);
            String user = context.getBean(JwtGenerator.class).generateAccessToken(new AutoAuthUser("alice", List.of("USER"), null));
            String admin = context.getBean(JwtGenerator.class).generateAccessToken(new AutoAuthUser("alice", List.of("ADMIN"), null));
            mvc.perform(get("/health")).andExpect(status().isOk());
            // The application chose not to honor @PublicEndpoint in its custom chain.
            mvc.perform(get("/api/public")).andExpect(status().isUnauthorized());
            mvc.perform(get("/api/private").header("Authorization", "Bearer " + user)).andExpect(status().isOk());
            mvc.perform(get("/api/admin").header("Authorization", "Bearer " + user)).andExpect(status().isForbidden());
            mvc.perform(get("/api/admin").header("Authorization", "Bearer " + admin)).andExpect(status().isOk());
            mvc.perform(get("/ops/status").header("Authorization", "Bearer " + admin)).andExpect(status().isForbidden());
            mvc.perform(get("/health").header("Authorization", "Bearer invalid")).andExpect(status().isUnauthorized());
            mvc.perform(get("/unknown")).andExpect(status().isUnauthorized());
        });
    }

    @Test
    void cookieAuthenticationRequiresRealCsrfTokenForStateChangesIncludingLogin() {
        withKeys().withPropertyValues("autoauth.cookie-secure=false").run(context -> {
            MockMvc mvc = mvc(context);
            var pair = context.getBean(JwtGenerator.class).generateTokenPair(new AutoAuthUser("alice", List.of("USER"), null));
            Cookie access = new Cookie("AUTOAUTH", pair.accessToken());
            mvc.perform(get("/api/private").cookie(access)).andExpect(status().isOk())
                    .andExpect(content().string("alice"));
            mvc.perform(post("/api/private").cookie(access)).andExpect(status().isForbidden());
            mvc.perform(post("/api/login")).andExpect(status().isForbidden());
            var bootstrap = mvc.perform(get("/autoauth/csrf")).andExpect(status().isOk()).andReturn();
            Cookie csrf = bootstrap.getResponse().getCookie("XSRF-TOKEN");
            assertThat(csrf).isNotNull();
            mvc.perform(post("/api/private").cookie(access, csrf).header("X-XSRF-TOKEN", csrf.getValue()))
                    .andExpect(status().isOk());
            mvc.perform(post("/api/private").cookie(access, csrf).header("X-XSRF-TOKEN", "wrong"))
                    .andExpect(status().isForbidden());
            mvc.perform(post("/api/login").cookie(csrf).header("X-XSRF-TOKEN", csrf.getValue()))
                    .andExpect(status().isOk());
            // Supplying a bearer header does not bypass CSRF while cookie transport is enabled.
            mvc.perform(post("/api/private").header("Authorization", "Bearer " + pair.accessToken()))
                    .andExpect(status().isForbidden());
            mvc.perform(get("/api/private")).andExpect(status().isUnauthorized());
            assertThat(bootstrap.getRequest().getSession(false)).isNull();
        });
    }

    @Test
    void bearerOnlyModeIgnoresCookiesAndRequiresNoCsrf() {
        withKeys().withPropertyValues("autoauth.transport=BEARER").run(context -> {
            MockMvc mvc = mvc(context);
            String token = context.getBean(JwtGenerator.class).generateAccessToken(new AutoAuthUser("alice", null, null));
            mvc.perform(post("/api/private").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
            mvc.perform(get("/api/private").cookie(new Cookie("AUTOAUTH", token))).andExpect(status().isUnauthorized());
            mvc.perform(get("/api/private")).andExpect(status().isUnauthorized());
            assertThat(context.getBean(OpenAPI.class).getComponents().getSecuritySchemes()).doesNotContainKey("JWT-Cookie");
        });
    }

    @Test
    void refreshTokensNeverAuthenticateHttpAndInvalidTokensStopPublicHandlers() {
        withKeys().run(context -> {
            MockMvc mvc = mvc(context);
            String refresh = context.getBean(JwtGenerator.class).generateRefreshToken(new AutoAuthUser("alice", null, null));
            mvc.perform(get("/api/private").header("Authorization", "Bearer " + refresh))
                    .andExpect(status().isUnauthorized());
            mvc.perform(get("/api/private").cookie(new Cookie("AUTOAUTH_REFRESH", refresh)))
                    .andExpect(status().isUnauthorized());
            mvc.perform(get("/api/private").cookie(new Cookie("AUTOAUTH", refresh)))
                    .andExpect(status().isUnauthorized());
            mvc.perform(get("/api/public").header("Authorization", "Bearer invalid"))
                    .andExpect(status().isUnauthorized()).andExpect(header().string("WWW-Authenticate", "Bearer"));
        });
    }

    @Test
    void rolesDenyWrongUserAndAcceptOptionalSpringPrefix() {
        withKeys().run(context -> {
            MockMvc mvc = mvc(context);
            var generator = context.getBean(JwtGenerator.class);
            String user = generator.generateAccessToken(new AutoAuthUser("alice", List.of("USER"), null));
            String admin = generator.generateAccessToken(new AutoAuthUser("admin", List.of("ROLE_ADMIN"), null));
            mvc.perform(get("/api/admin").header("Authorization", "Bearer " + user)).andExpect(status().isForbidden());
            mvc.perform(get("/api/admin").header("Authorization", "Bearer " + admin)).andExpect(status().isOk());
        });
    }

    @Test
    void corsRejectsUnconfiguredOriginsAndAllowsOnlyExplicitOrigins() {
        withKeys().run(context -> mvc(context).perform(options("/api/private").header("Origin", "https://evil.test")
                .header("Access-Control-Request-Method", "POST")).andExpect(status().isForbidden()));
        withKeys().withPropertyValues("autoauth.allowed-origins[0]=https://app.test").run(context -> {
            mvc(context).perform(options("/api/private").header("Origin", "https://app.test")
                    .header("Access-Control-Request-Method", "POST")
                    .header("Access-Control-Request-Headers", "X-XSRF-TOKEN"))
                    .andExpect(status().isOk()).andExpect(header().string("Access-Control-Allow-Origin", "https://app.test"))
                    .andExpect(header().string("Access-Control-Allow-Credentials", "true"));
            mvc(context).perform(options("/api/private").header("Origin", "https://evil.test")
                    .header("Access-Control-Request-Method", "POST")).andExpect(status().isForbidden());
        });
    }

    @Test
    void verifierOnlyAndApplicationOverridesWork() {
        runner.withPropertyValues("autoauth.public-key=" + TestKeys.properties().getPublicKey()).run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(JwtValidator.class).doesNotHaveBean(JwtGenerator.class);
            String token = new JwtGenerator(new JwtKeyProvider(TestKeys.properties()), TestKeys.properties())
                    .generateAccessToken(new AutoAuthUser("alice", null, null));
            mvc(context).perform(get("/api/private").header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        });
        withKeys().withUserConfiguration(CustomSecurity.class).run(context -> {
            assertThat(context).hasNotFailed().hasSingleBean(SecurityFilterChain.class);
            mvc(context).perform(get("/api/public")).andExpect(status().isForbidden());
        });
        runner.withPropertyValues("autoauth.enabled=false").run(context ->
                assertThat(context).doesNotHaveBean(JwtValidator.class).doesNotHaveBean(SecurityFilterChain.class));
        runner.run(context -> assertThat(context.getStartupFailure()).isNotNull());
    }

    @Test
    void cookieBudgetBindsWithoutRestrictingLargerBearerTokens() {
        withKeys().withPropertyValues("autoauth.transport=BEARER", "autoauth.max-cookie-size=512").run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context.getBean(AutoAuthProperties.class).getMaxCookieSize()).isEqualTo(512);
            String token = context.getBean(JwtGenerator.class).generateAccessToken(
                    new AutoAuthUser("alice", List.of("USER"), java.util.Map.of("large", "a".repeat(3000))));
            assertThat(token.length()).isGreaterThan(3800);
            mvc(context).perform(get("/api/private").header("Authorization", "Bearer " + token))
                    .andExpect(status().isOk()).andExpect(content().string("alice"));
        });
    }

    @Test
    void rejectsInvalidConfigurationAndPreservesExplicitDocumentationExposure() {
        for (String invalid : List.of("autoauth.issuer=", "autoauth.expiration-minutes=0",
                "autoauth.cookie-same-site=invalid", "autoauth.allowed-origins[0]=*",
                "autoauth.refresh-cookie-name=AUTOAUTH", "autoauth.max-cookie-size=0", "autoauth.max-cookie-size=-1")) {
            withKeys().withPropertyValues(invalid).run(context -> assertThat(context.getStartupFailure()).isNotNull());
        }
        withKeys().run(context ->
                mvc(context).perform(get("/v3/api-docs")).andExpect(status().isUnauthorized()));
        withKeys().withPropertyValues("autoauth.swagger-public=true").run(context -> {
            // With no springdoc handlers registered these paths do not become public.
            mvc(context).perform(get("/v3/api-docs")).andExpect(status().isUnauthorized());
            mvc(context).perform(get("/swagger-ui/index.html")).andExpect(status().isUnauthorized());
        });
    }

    @Test
    void swaggerOperationsDistinguishPublicRoutesAndRoleRules() {
        withKeys().run(context -> {
            var customizer = context.getBean("autoAuthOperationSecurity", OperationCustomizer.class);
            Operation publicOperation = customizer.customize(new Operation(),
                    new HandlerMethod(new Routes(), Routes.class.getMethod("open")));
            assertThat(publicOperation.getSecurity()).isEmpty();
            Operation admin = customizer.customize(new Operation(),
                    new HandlerMethod(new Routes(), Routes.class.getMethod("admin")));
            assertThat(admin.getExtensions()).containsEntry("x-autoauth-roles", List.of("ADMIN"));
        });
    }

    @Test
    void swaggerDefaultsPreserveExplicitSchemesRequirementsAndAnonymousDocuments() {
        var config = new AutoAuthSwaggerConfig();
        var customizer = config.autoAuthDocumentSecurity(new AutoAuthProperties());
        var explicitScheme = new SecurityScheme().type(SecurityScheme.Type.APIKEY).name("Application-Token")
                .in(SecurityScheme.In.HEADER);
        var explicit = new OpenAPI().components(new io.swagger.v3.oas.models.Components()
                .addSecuritySchemes("JWT-Bearer", explicitScheme))
                .security(List.of(new io.swagger.v3.oas.models.security.SecurityRequirement().addList("Application")));
        customizer.customise(explicit);
        customizer.customise(explicit);
        assertThat(explicit.getComponents().getSecuritySchemes().get("JWT-Bearer")).isSameAs(explicitScheme);
        assertThat(explicit.getSecurity()).hasSize(1);
        assertThat(explicit.getSecurity().getFirst()).containsKey("Application");
        var anonymous = new OpenAPI().security(List.of());
        customizer.customise(anonymous);
        assertThat(anonymous.getSecurity()).isEmpty();
        assertThat(anonymous.getComponents().getSecuritySchemes()).containsKeys("JWT-Bearer", "JWT-Cookie");
    }

    private WebApplicationContextRunner withKeys() {
        var properties = TestKeys.properties();
        return runner.withPropertyValues("autoauth.private-key=" + properties.getPrivateKey(),
                "autoauth.public-key=" + properties.getPublicKey());
    }
    private MockMvc mvc(WebApplicationContext context) {
        return MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    @Configuration(proxyBeanMethods = false)
    @EnableWebMvc
    @Import({Routes.class, PublicRoutes.class, RootPublicRoutes.class, OtherRoutes.class})
    static class WebConfig {}
    @Configuration(proxyBeanMethods = false)
    static class CustomSecurity {
        @Bean SecurityFilterChain applicationSecurity(HttpSecurity http) throws Exception {
            return http.csrf(csrf -> csrf.disable()).authorizeHttpRequests(auth -> auth.anyRequest().denyAll())
                    .exceptionHandling(ex -> ex.authenticationEntryPoint((request, response, failure) -> response.setStatus(403)))
                    .build();
        }
    }
    @Configuration(proxyBeanMethods = false)
    static class MultipleChains {
        @Bean @Order(1) SecurityFilterChain operations(HttpSecurity http) throws Exception {
            return http.securityMatcher("/ops/**").csrf(csrf -> csrf.disable())
                    .authorizeHttpRequests(auth -> auth.anyRequest().denyAll())
                    .exceptionHandling(ex -> ex.authenticationEntryPoint((request, response, failure) -> response.setStatus(403)))
                    .build();
        }
        @Bean @Order(2) SecurityFilterChain application(HttpSecurity http, JwtValidator validator,
                                                     AutoAuthProperties properties) throws Exception {
            return http.csrf(csrf -> csrf.disable())
                    .sessionManagement(session -> session.sessionCreationPolicy(org.springframework.security.config.http.SessionCreationPolicy.STATELESS))
                    .authorizeHttpRequests(auth -> auth.requestMatchers("/health").permitAll().anyRequest().authenticated())
                    .exceptionHandling(ex -> ex.authenticationEntryPoint(new com.autoauth.exception.AutoAuthAuthenticationEntryPoint())
                            .accessDeniedHandler(new com.autoauth.exception.AutoAuthAccessDeniedHandler()))
                    .addFilterBefore(new JwtAuthenticationFilter(validator, properties), UsernamePasswordAuthenticationFilter.class)
                    .build();
        }
    }
    @RestController @RequestMapping("/api")
    public static class Routes {
        @PublicEndpoint @GetMapping("/public") public String open() { return "public"; }
        @PostMapping("/public") public String protectedPost() { return "protected"; }
        @PublicEndpoint @PostMapping("/login") public String login() { return "application login stub"; }
        @GetMapping("/configured") public String configured() { return "configured"; }
        @PostMapping("/configured") public String configuredPost() { return "configured post"; }
        @GetMapping("/private") public String secured() { return AuthContext.getCurrentUserId().orElseThrow(); }
        @PostMapping("/private") public String post() { return "posted"; }
        @RequiresRole("ADMIN") @GetMapping("/admin") public String admin() { return "admin"; }
        @PublicEndpoint @GetMapping(path="/choice", params="public") public String publicChoice() { return "public"; }
        @GetMapping(path="/choice", params="!public") public String privateChoice() { return "private"; }
    }
    @PublicEndpoint @RestController @RequestMapping("/public")
    public static class PublicRoutes { @GetMapping("/status") public String status() { return "ok"; } }
    @PublicEndpoint @RestController
    public static class RootPublicRoutes { @GetMapping("/health") public String health() { return "ok"; } }
    @RestController
    public static class OtherRoutes { @GetMapping("/public/private") public String privateRoute() { return "private"; } }
}
