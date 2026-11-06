package com.autoauth.config;

import com.autoauth.annotation.PublicEndpoint;
import com.autoauth.annotation.RequiresRole;
import com.autoauth.support.TestKeys;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(classes = SwaggerConsumerTest.App.class)
@AutoConfigureMockMvc
class SwaggerConsumerTest {
    @Autowired MockMvc mvc;
    @Autowired org.springdoc.core.properties.SwaggerUiConfigProperties swagger;
    @DynamicPropertySource static void configuration(DynamicPropertyRegistry registry) {
        registry.add("autoauth.private-key", () -> TestKeys.properties().getPrivateKey());
        registry.add("autoauth.swagger-public", () -> "true");
        registry.add("autoauth.cookie-secure", () -> "false");
    }
    @Test void realSwaggerConfigurationAndOpenApiIncludeAutomaticAuthenticationAndCsrf() throws Exception {
        org.assertj.core.api.Assertions.assertThat(swagger.getCsrf().isEnabled()).isTrue();
        mvc.perform(get("/v3/api-docs/swagger-config")).andExpect(status().isOk())
                .andExpect(cookie().exists("XSRF-TOKEN"));
        mvc.perform(get("/v3/api-docs")).andExpect(status().isOk())
                .andExpect(jsonPath("$.components.securitySchemes.JWT-Bearer.scheme").value("bearer"))
                .andExpect(jsonPath("$.components.securitySchemes.JWT-Cookie.name").value("AUTOAUTH"))
                .andExpect(jsonPath("$.paths['/demo/public'].get.security").isEmpty())
                .andExpect(jsonPath("$.paths['/demo/admin'].get['x-autoauth-roles'][0]").value("ADMIN"));
        mvc.perform(get("/swagger-ui/index.html")).andExpect(status().isOk());
        mvc.perform(get("/swagger-ui/swagger-initializer.js")).andExpect(status().isOk())
                .andExpect(content().string(org.hamcrest.Matchers.containsString("X-XSRF-TOKEN")));
    }
    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration
    @Import(Routes.class)
    static class App {}
    @RestController
    public static class Routes {
        @PublicEndpoint @GetMapping("/demo/public") public String open() { return "public"; }
        @RequiresRole("ADMIN") @GetMapping("/demo/admin") public String admin() { return "admin"; }
    }
}
