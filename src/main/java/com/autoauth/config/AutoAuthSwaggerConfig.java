package com.autoauth.config;

import com.autoauth.annotation.RequiresRole;
import com.autoauth.aop.RoleRuleResolver;
import com.autoauth.util.EndpointScanner;
import io.swagger.v3.oas.models.*;
import io.swagger.v3.oas.models.security.*;
import org.springdoc.core.customizers.GlobalOperationCustomizer;
import org.springdoc.core.customizers.GlobalOpenApiCustomizer;
import org.springdoc.core.properties.SwaggerUiConfigProperties;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.*;
import java.util.ArrayList;
import java.util.List;

@Configuration(proxyBeanMethods = false)
public class AutoAuthSwaggerConfig {
    @Bean
    @ConditionalOnMissingBean
    public OpenAPI autoAuthOpenApi(AutoAuthProperties properties) {
        var api = new OpenAPI();
        mergeSecurity(api, properties);
        return api;
    }

    @Bean
    public GlobalOpenApiCustomizer autoAuthDocumentSecurity(AutoAuthProperties properties) {
        return api -> mergeSecurity(api, properties);
    }

    private static void mergeSecurity(OpenAPI api, AutoAuthProperties properties) {
        if (api.getComponents() == null) api.setComponents(new Components());
        var components = api.getComponents();
        if (components.getSecuritySchemes() == null || !components.getSecuritySchemes().containsKey("JWT-Bearer")) {
            components.addSecuritySchemes("JWT-Bearer",
                    new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT"));
        }
        List<SecurityRequirement> requirements = new ArrayList<>();
        requirements.add(new SecurityRequirement().addList("JWT-Bearer"));
        if (properties.isCookieEnabled()) {
            if (components.getSecuritySchemes() == null || !components.getSecuritySchemes().containsKey("JWT-Cookie")) {
                components.addSecuritySchemes("JWT-Cookie", new SecurityScheme().type(SecurityScheme.Type.APIKEY)
                    .in(SecurityScheme.In.COOKIE).name(properties.getCookieName())
                    .description("Set by your application's login endpoint; the browser sends this HttpOnly cookie automatically."));
            }
            requirements.add(new SecurityRequirement().addList("JWT-Cookie"));
        }
        // null means no application choice; an explicit empty list deliberately disables defaults.
        if (api.getSecurity() == null) api.setSecurity(requirements);
    }

    @Bean
    public GlobalOperationCustomizer autoAuthOperationSecurity() {
        return (operation, handler) -> {
            if (EndpointScanner.isPublic(handler)) operation.setSecurity(List.of());
            RequiresRole roles = RoleRuleResolver.resolve(handler.getMethod(), handler.getBeanType());
            if (roles != null) {
                operation.addExtension("x-autoauth-roles", List.of(roles.value()));
                operation.addExtension("x-autoauth-require-all", roles.requireAll());
            }
            return operation;
        };
    }

    @Bean
    public static BeanPostProcessor autoAuthSwaggerCsrfConfiguration(
            org.springframework.core.env.Environment environment) {
        return new BeanPostProcessor() {
            @Override
            public Object postProcessAfterInitialization(Object bean, String beanName) {
                if (bean instanceof SwaggerUiConfigProperties swagger
                        && !"BEARER".equalsIgnoreCase(environment.getProperty("autoauth.transport"))) {
                    swagger.getCsrf().setEnabled(true);
                    swagger.getCsrf().setCookieName("XSRF-TOKEN");
                    swagger.getCsrf().setHeaderName("X-XSRF-TOKEN");
                }
                return bean;
            }
        };
    }
}
