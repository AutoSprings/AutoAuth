package com.autoauth.config;

import com.autoauth.support.TestKeys;
import org.junit.jupiter.api.Test;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.*;

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(classes = CustomSwaggerPathsTest.App.class, properties = {
        "autoauth.swagger-public=true", "autoauth.cookie-secure=false",
        "springdoc.api-docs.path=/docs/schema", "springdoc.swagger-ui.path=/docs/explore"})
@AutoConfigureMockMvc
class CustomSwaggerPathsTest {
    @Autowired MockMvc mvc;
    @DynamicPropertySource static void keys(DynamicPropertyRegistry registry) {
        registry.add("autoauth.private-key", () -> TestKeys.properties().getPrivateKey());
    }

    @Test void customDocumentationPathsAndResourcesWorkUnderAContextPath() throws Exception {
        for (String path : new String[]{"/docs/schema", "/docs/schema/demo", "/docs/schema/swagger-config"}) {
            mvc.perform(get("/app" + path).contextPath("/app")).andExpect(status().isOk())
                    .andExpect(cookie().exists("XSRF-TOKEN"));
        }
        mvc.perform(get("/app/docs/schema.yaml").contextPath("/app")).andExpect(status().isOk());
        mvc.perform(get("/app/docs/explore").contextPath("/app")).andExpect(status().is3xxRedirection());
        mvc.perform(get("/app/docs/swagger-ui/index.html").contextPath("/app")).andExpect(status().isOk());
        mvc.perform(get("/app/docs/swagger-ui/swagger-initializer.js").contextPath("/app"))
                .andExpect(status().isOk()).andExpect(content().string(containsString("X-XSRF-TOKEN")));
    }

    @Test void docsExposureDoesNotPermitOldUrlsSiblingRoutesOrApplicationHandlersInsideDocsPrefixes() throws Exception {
        for (String path : new String[]{"/v3/api-docs", "/swagger-ui.html", "/docs/private",
                "/docs/schema/private", "/docs/swagger-ui/private", "/docs/explore/private"}) {
            mvc.perform(get(path)).andExpect(status().isUnauthorized());
        }
        // CSRF can be satisfied without granting anonymous POST access to a documentation URL.
        mvc.perform(post("/docs/schema").with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf()))
                .andExpect(status().isUnauthorized());
    }

    @Configuration(proxyBeanMethods = false) @EnableAutoConfiguration
    @Import({SwaggerConsumerTest.Routes.class, ApplicationRoutes.class})
    static class App {
        @Bean GroupedOpenApi demoApi() { return GroupedOpenApi.builder().group("demo").pathsToMatch("/demo/**").build(); }
    }
    @RestController public static class ApplicationRoutes {
        @GetMapping({"/v3/api-docs", "/swagger-ui.html", "/docs/private", "/docs/schema/private",
                "/docs/swagger-ui/private", "/docs/explore/private"})
        public String privateRoute() { return "protected application handler"; }
    }
}
