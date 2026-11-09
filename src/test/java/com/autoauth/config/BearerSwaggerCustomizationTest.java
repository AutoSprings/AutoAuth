package com.autoauth.config;

import com.autoauth.support.TestKeys;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(classes = CustomSwaggerPathsTest.App.class, properties = {
        "autoauth.transport=BEARER", "autoauth.swagger-public=true",
        "springdoc.api-docs.path=/docs/schema", "springdoc.swagger-ui.path=/docs/explore"})
@AutoConfigureMockMvc
class BearerSwaggerCustomizationTest {
    @Autowired MockMvc mvc;
    @DynamicPropertySource static void keys(DynamicPropertyRegistry registry) {
        registry.add("autoauth.private-key", () -> TestKeys.properties().getPrivateKey());
    }
    @Test void customAndGroupedDocumentsKeepBearerSecurityWithoutCookieSecurity() throws Exception {
        for (String path : new String[]{"/docs/schema", "/docs/schema/demo"}) {
            mvc.perform(get(path)).andExpect(status().isOk())
                    .andExpect(jsonPath("$.info.title").value("Consumer API"))
                    .andExpect(jsonPath("$.components.securitySchemes.JWT-Bearer.scheme").value("bearer"))
                    .andExpect(jsonPath("$.components.securitySchemes.JWT-Cookie").doesNotExist())
                    .andExpect(jsonPath("$.security.length()").value(1))
                    .andExpect(jsonPath("$.paths['/demo/public'].get.security").isEmpty())
                    .andExpect(jsonPath("$.paths['/demo/admin'].get['x-autoauth-roles'][0]").value("ADMIN"));
        }
    }
}
