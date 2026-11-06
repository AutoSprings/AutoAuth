package com.autoauth.annotation;

import java.lang.annotation.*;

/**
 * Requires any listed role, or every role when requireAll=true.
 * Role names are case-sensitive and accept an optional ROLE_ prefix. No hierarchy is implied.
 * Applies through Spring proxies; private/final methods and self-invocation are unsupported.
 * A method rule overrides a class rule.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequiresRole {
    String[] value();
    boolean requireAll() default false;
}
