package com.autoauth.config;

import com.autoauth.jwt.JwtGenerator;
import com.autoauth.model.AutoAuthUser;
import com.autoauth.support.TestKeys;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(classes = CustomSwaggerPathsTest.App.class, properties = {
        "autoauth.swagger-public=false", "autoauth.cookie-secure=false",
        "springdoc.api-docs.path=/docs/schema", "springdoc.swagger-ui.path=/docs/explore"})
@AutoConfigureMockMvc
class PrivateSwaggerPathsTest {
    @Autowired MockMvc mvc;
    @Autowired JwtGenerator generator;
    @DynamicPropertySource static void keys(DynamicPropertyRegistry registry) {
        registry.add("autoauth.private-key", () -> TestKeys.properties().getPrivateKey());
    }

    @Test void customDocumentationStillRequiresAuthenticationUnlessDeliberatelyExposed() throws Exception {
        String token = generator.generateAccessToken(new AutoAuthUser("alice", null, null));
        for (String path : new String[]{"/docs/schema", "/docs/schema/demo", "/docs/schema/swagger-config",
                "/docs/swagger-ui/index.html"}) {
            mvc.perform(get(path)).andExpect(status().isUnauthorized());
            mvc.perform(get(path).header("Authorization", "Bearer " + token)).andExpect(status().isOk());
        }
        mvc.perform(get("/docs/explore")).andExpect(status().isUnauthorized());
    }
}
