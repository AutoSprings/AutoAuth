package com.autoauth.config;

import com.autoauth.annotation.RequiresRole;
import com.autoauth.util.EndpointScanner;
import io.swagger.v3.oas.models.*;
import io.swagger.v3.oas.models.security.*;
import org.springdoc.core.customizers.OperationCustomizer;
import org.springdoc.core.properties.SwaggerUiConfigProperties;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.AnnotatedElementUtils;
import java.util.ArrayList;
import java.util.List;

@Configuration(proxyBeanMethods = false)
public class AutoAuthSwaggerConfig {
    @Bean
    @ConditionalOnMissingBean
    public OpenAPI autoAuthOpenApi(AutoAuthProperties properties) {
        var components = new Components().addSecuritySchemes("JWT-Bearer",
                new SecurityScheme().type(SecurityScheme.Type.HTTP).scheme("bearer").bearerFormat("JWT"));
        List<SecurityRequirement> requirements = new ArrayList<>();
        requirements.add(new SecurityRequirement().addList("JWT-Bearer"));
        if (properties.isCookieEnabled()) {
            components.addSecuritySchemes("JWT-Cookie", new SecurityScheme().type(SecurityScheme.Type.APIKEY)
                    .in(SecurityScheme.In.COOKIE).name(properties.getCookieName())
                    .description("Set by your application's login endpoint; the browser sends this HttpOnly cookie automatically."));
            requirements.add(new SecurityRequirement().addList("JWT-Cookie"));
        }
        return new OpenAPI().components(components).security(requirements);
    }

    @Bean
    public OperationCustomizer autoAuthOperationSecurity() {
        return (operation, handler) -> {
            if (EndpointScanner.isPublic(handler)) operation.setSecurity(List.of());
            RequiresRole roles = AnnotatedElementUtils.findMergedAnnotation(handler.getMethod(), RequiresRole.class);
            if (roles == null) roles = AnnotatedElementUtils.findMergedAnnotation(handler.getBeanType(), RequiresRole.class);
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
