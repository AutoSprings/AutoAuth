package com.autoauth.config;

import com.autoauth.exception.AutoAuthAccessDeniedHandler;
import com.autoauth.exception.AutoAuthAuthenticationEntryPoint;
import com.autoauth.filter.JwtAuthenticationFilter;
import com.autoauth.jwt.JwtValidator;
import com.autoauth.util.EndpointScanner;

import org.springframework.context.annotation.Bean;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;
import java.util.ArrayList;

@Configuration
@EnableWebSecurity
public class SecurityFilterChainConfig {

    private final AutoAuthProperties properties;
    private final JwtValidator jwtValidator;
    private final ApplicationContext applicationContext;

    public SecurityFilterChainConfig(AutoAuthProperties properties, JwtValidator jwtValidator, ApplicationContext applicationContext) {
        this.properties = properties;
        this.jwtValidator = jwtValidator;
        this.applicationContext = applicationContext;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        AutoAuthAuthenticationEntryPoint entryPoint = new AutoAuthAuthenticationEntryPoint();
        AutoAuthAccessDeniedHandler deniedHandler = new AutoAuthAccessDeniedHandler();

        JwtAuthenticationFilter jwtFilter = new JwtAuthenticationFilter(jwtValidator, properties.getCookieName());

        EndpointScanner scanner = new EndpointScanner(applicationContext);
        List<String> scannedPaths = scanner.getPublicPaths();

        List<String> yamlPaths = properties.getPublicPaths();
        if (yamlPaths == null) yamlPaths = new ArrayList<>();

        List<String> allPublicPaths = new ArrayList<>(scannedPaths);
        allPublicPaths.addAll(yamlPaths);

        if (isSwaggerPresent()) {
            allPublicPaths.add("/v3/api-docs/**");
            allPublicPaths.add("/swagger-ui/**");
            allPublicPaths.add("/swagger-ui.html");
            System.out.println("[AutoAuth] Detected Swagger on classpath. Automatically whitelisted Swagger UI Paths.");
        }

        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint(entryPoint)
                        .accessDeniedHandler(deniedHandler)
                )
                .authorizeHttpRequests(auth -> {

                    if (!allPublicPaths.isEmpty()) {
                        auth.requestMatchers(allPublicPaths.toArray(new String[0])).permitAll();
                    }

                    auth.anyRequest().authenticated();
                })
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();

    }

    private boolean isSwaggerPresent() {

        try {
            Class.forName("io.swagger.v3.oas.models.OpenAPI");
            return true;
        } catch (ClassNotFoundException e) {
            return false;
        }

    }

    private CorsConfigurationSource corsConfigurationSource() {

        CorsConfiguration configuration = new CorsConfiguration();

        List<String> allowedOrigins = properties.getAllowedOrigins();

        if (allowedOrigins == null || allowedOrigins.isEmpty()) {
            configuration.setAllowedOriginPatterns(List.of("*"));
        } else {
            configuration.setAllowedOrigins(allowedOrigins);
        }

        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;

    }

}
