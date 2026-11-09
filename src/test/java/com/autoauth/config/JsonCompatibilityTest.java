package com.autoauth.config;

import com.autoauth.annotation.PublicEndpoint;
import com.autoauth.jwt.JwtGenerator;
import com.autoauth.jwt.JwtValidator;
import com.autoauth.model.AutoAuthUser;
import com.autoauth.model.TokenPair;
import com.autoauth.support.TestKeys;
import com.autoauth.util.AuthContext;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter;
import tools.jackson.databind.json.JsonMapper;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Exercises Boot's HTTP Jackson 3 mapper alongside JJWT's runtime Jackson 2 adapter. */
@SpringBootTest(classes = JsonCompatibilityTest.App.class, properties = "autoauth.transport=BEARER")
@AutoConfigureMockMvc
class JsonCompatibilityTest {
    @Autowired MockMvc mvc;
    @Autowired JsonMapper httpJson;
    @Autowired JwtValidator validator;
    @Autowired RequestMappingHandlerAdapter handlers;

    @DynamicPropertySource
    static void keys(DynamicPropertyRegistry registry) {
        registry.add("autoauth.private-key", () -> TestKeys.properties().getPrivateKey());
    }

    @Test
    void bothJacksonFamiliesLoadWithJackson3HandlingHttp() throws Exception {
        assertThat(httpJson.version().getMajorVersion()).isEqualTo(3);
        assertThat(handlers.getMessageConverters()).anyMatch(JacksonJsonHttpMessageConverter.class::isInstance);
        assertThat(Class.forName("com.fasterxml.jackson.databind.ObjectMapper").getPackage().getImplementationVersion())
                .startsWith("2.");
        assertThat(Class.forName("io.jsonwebtoken.jackson.io.JacksonSerializer")).isNotNull();
    }

    @Test
    void nestedClaimsRoundTripThroughHttpJwtAndAuthenticatedHttpResponse() throws Exception {
        var identity = new AutoAuthUser("al\u00e9x", List.of("USER"), Map.of(
                "tenant", "acme", "active", true, "count", 7, "large", 1234567890123L,
                "ratio", 12.5, "text", "quotes: \" and newline\n and Unicode \u2603",
                "nested", Map.of("permissions", List.of("read", "write"), "enabled", true)));
        var issued = mvc.perform(post("/compat/issue").contentType(MediaType.APPLICATION_JSON)
                        .content(httpJson.writeValueAsString(identity)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.accessToken").isString())
                .andExpect(jsonPath("$.refreshToken").isString()).andReturn();
        TokenPair pair = httpJson.readValue(issued.getResponse().getContentAsByteArray(), TokenPair.class);
        assertThat(validator.validateAccessToken(pair.accessToken())).isEqualTo(identity);
        assertThat(validator.validateRefreshToken(pair.refreshToken()))
                .isEqualTo(new AutoAuthUser(identity.userId(), null, null));

        var authenticated = mvc.perform(get("/compat/identity").header("Authorization", "Bearer " + pair.accessToken()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.customClaims.nested.enabled").value(true)).andReturn();
        assertThat(httpJson.readValue(authenticated.getResponse().getContentAsByteArray(), AutoAuthUser.class))
                .isEqualTo(identity);
        mvc.perform(get("/compat/identity").header("Authorization", "Bearer " + pair.refreshToken()))
                .andExpect(status().isUnauthorized());
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @Import(Routes.class)
    static class App {}

    @RestController
    static class Routes {
        private final JwtGenerator generator;
        Routes(JwtGenerator generator) { this.generator = generator; }
        @PublicEndpoint @PostMapping("/compat/issue")
        TokenPair issue(@RequestBody AutoAuthUser identity) { return generator.generateTokenPair(identity); }
        @GetMapping("/compat/identity")
        AutoAuthUser identity() { return AuthContext.getCurrentUser().orElseThrow(); }
    }
}
