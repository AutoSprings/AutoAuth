package com.autoauth.config;

import com.autoauth.blacklist.CafeTokenBlackList;
import com.autoauth.blacklist.TokenBlackList;
import com.autoauth.controller.JwksController;
import com.autoauth.jwt.JwtGenerator;
import com.autoauth.jwt.JwtKeyProvider;
import com.autoauth.jwt.JwtValidator;
import com.autoauth.aop.RoleAspect;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.EnableAspectJAutoProxy;

import java.security.NoSuchAlgorithmException;
import java.time.Clock;

@AutoConfiguration
@EnableConfigurationProperties(AutoAuthProperties.class)
@Import({SecurityFilterChainConfig.class, AutoAuthSwaggerConfig.class})
@EnableAspectJAutoProxy
public class AutoAuthAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public JwtKeyProvider JwtKeyProvider(AutoAuthProperties properties) throws NoSuchAlgorithmException {
        return new JwtKeyProvider(properties);
    }

    @Bean
    @ConditionalOnMissingBean(Clock.class)
    public Clock autoAuthClock() {
        return Clock.systemUTC();
    }

    @Bean
    @ConditionalOnMissingBean
    public RoleAspect roleAspect() {
        return new RoleAspect();
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtGenerator jwtGenerator(JwtKeyProvider keyProvider, AutoAuthProperties properties) {
        return new JwtGenerator(keyProvider, properties);
    }

    @Bean
    @ConditionalOnMissingBean(TokenBlackList.class)
    public TokenBlackList tokenBlackList() {
        return new CafeTokenBlackList();
    }

    @Bean
    @ConditionalOnProperty(name = "autoauth.public-key")
    public JwksController jwksController(JwtKeyProvider keyProvider) {
        return new JwksController(keyProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtValidator jwtValidator(JwtKeyProvider keyProvider, TokenBlackList blackList, AutoAuthProperties properties, Clock clock) {
        return new JwtValidator(keyProvider, blackList, properties, clock);
    }

}
