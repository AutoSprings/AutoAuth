package com.autoauth.config;

import com.autoauth.exception.*;
import com.autoauth.filter.JwtAuthenticationFilter;
import com.autoauth.jwt.JwtValidator;
import com.autoauth.util.EndpointScanner;
import com.autoauth.util.SwaggerEndpointMatcher;
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
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.http.HttpMethod;
import org.springframework.web.cors.*;
import java.util.List;
import java.util.ArrayList;

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
        var paths = PathPatternRequestMatcher.withDefaults();
        List<RequestMatcher> publicMatchers = new ArrayList<>();
        publicMatchers.add(paths.matcher(HttpMethod.GET, "/autoauth/csrf"));
        if (properties.isSwaggerPublic()) {
            publicMatchers.add(new SwaggerEndpointMatcher(context));
        }
        properties.getPublicPaths().forEach(path -> publicMatchers.add(paths.matcher(path)));
        publicMatchers.add(new EndpointScanner(context));
        // Authorization and stale-cookie recovery must agree on exactly which requests are public.
        var publicRequests = new OrRequestMatcher(publicMatchers);
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
                .authorizeHttpRequests(auth -> auth.requestMatchers(publicRequests).permitAll().anyRequest().authenticated())
                .addFilterBefore(new JwtAuthenticationFilter(validator, properties, publicRequests), UsernamePasswordAuthenticationFilter.class);
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
