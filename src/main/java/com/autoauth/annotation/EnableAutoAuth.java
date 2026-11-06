package com.autoauth.annotation;

import com.autoauth.config.AutoAuthAutoConfiguration;
import org.springframework.context.annotation.Import;
import java.lang.annotation.*;

/**
 * Explicitly imports AutoAuth when Spring Boot auto-configuration discovery is not used.
 * Boot applications activate AutoAuth from the dependency; autoauth.enabled=false disables it.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Documented
@Import(AutoAuthAutoConfiguration.class)
public @interface EnableAutoAuth {}
