package com.autoauth.config;

import com.autoauth.aop.RoleAspect;
import com.autoauth.controller.CsrfController;
import com.autoauth.jwt.*;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.*;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.*;
import java.time.Clock;

@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(prefix = "autoauth", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(AutoAuthProperties.class)
@Import({SecurityFilterChainConfig.class, AutoAuthSwaggerConfig.class})
@EnableAspectJAutoProxy
public class AutoAuthAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean
    public JwtKeyProvider jwtKeyProvider(AutoAuthProperties properties) { return new JwtKeyProvider(properties); }

    @Bean
    @ConditionalOnMissingBean
    public Clock autoAuthClock() { return Clock.systemUTC(); }

    @Bean
    @ConditionalOnMissingBean
    public RoleAspect roleAspect() { return new RoleAspect(); }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "autoauth", name = "private-key")
    public JwtGenerator jwtGenerator(JwtKeyProvider keys, AutoAuthProperties properties, Clock clock) {
        return new JwtGenerator(keys, properties, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtValidator jwtValidator(JwtKeyProvider keys, AutoAuthProperties properties, Clock clock) {
        return new JwtValidator(keys, properties, clock);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtCookies jwtCookies(AutoAuthProperties properties) { return new JwtCookies(properties); }

    @Bean
    @ConditionalOnMissingBean
    public CsrfController csrfController() { return new CsrfController(); }
}
