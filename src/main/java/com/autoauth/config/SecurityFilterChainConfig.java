package com.autoauth.config;

import com.autoauth.exception.*;
import com.autoauth.filter.JwtAuthenticationFilter;
import com.autoauth.jwt.JwtValidator;
import com.autoauth.util.EndpointScanner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.http.HttpMethod;
import org.springframework.web.cors.*;
import java.util.List;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityFilterChainConfig {
    @Bean
    @ConditionalOnMissingBean(SecurityFilterChain.class)
    public SecurityFilterChain securityFilterChain(HttpSecurity http, AutoAuthProperties properties,
                                                  JwtValidator validator, ApplicationContext context) throws Exception {
        properties.validate();
        var entryPoint = new AutoAuthAuthenticationEntryPoint();
        var deniedHandler = new AutoAuthAccessDeniedHandler();
        if (properties.isCookieEnabled()) {
            var repository = CookieCsrfTokenRepository.withHttpOnlyFalse();
            repository.setCookieCustomizer(cookie -> cookie.secure(properties.isCookieSecure())
                    .sameSite(properties.getCookieSameSite()).path("/"));
            // Standard X-XSRF-TOKEN headers used by SPAs and Swagger carry the raw cookie token.
            var handler = new CsrfTokenRequestAttributeHandler();
            handler.setCsrfRequestAttributeName(null); // Materialize the cookie on safe requests too.
            http.csrf(csrf -> csrf.csrfTokenRepository(repository).csrfTokenRequestHandler(handler));
        } else {
            http.csrf(csrf -> csrf.disable());
        }
        http.cors(cors -> cors.configurationSource(corsConfigurationSource(properties)))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .logout(logout -> logout.disable())
                .requestCache(cache -> cache.disable())
                .exceptionHandling(ex -> ex.authenticationEntryPoint(entryPoint).accessDeniedHandler(deniedHandler))
                .authorizeHttpRequests(auth -> {
                    auth.requestMatchers(HttpMethod.GET, "/autoauth/csrf").permitAll();
                    if (properties.isSwaggerPublic()) {
                        auth.requestMatchers(HttpMethod.GET, "/v3/api-docs", "/v3/api-docs/**",
                                "/swagger-ui/**", "/swagger-ui.html").permitAll();
                    }
                    if (!properties.getPublicPaths().isEmpty()) {
                        auth.requestMatchers(properties.getPublicPaths().toArray(String[]::new)).permitAll();
                    }
                    auth.requestMatchers(new EndpointScanner(context)).permitAll();
                    auth.anyRequest().authenticated();
                })
                .addFilterBefore(new JwtAuthenticationFilter(validator, properties), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    private CorsConfigurationSource corsConfigurationSource(AutoAuthProperties properties) {
        var config = new CorsConfiguration();
        config.setAllowedOrigins(properties.getAllowedOrigins());
        config.setAllowedMethods(List.of("GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-XSRF-TOKEN"));
        config.setAllowCredentials(properties.isCookieEnabled());
        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
