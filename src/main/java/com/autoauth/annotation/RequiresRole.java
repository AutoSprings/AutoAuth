package com.autoauth.annotation;

import java.lang.annotation.*;

/**
 * Requires any listed role, or every role when requireAll=true.
 * Role names are case-sensitive and accept an optional ROLE_ prefix. No hierarchy is implied.
 * Applies through Spring proxies. Explicit private/static role declarations and methods
 * that the configured proxy cannot protect fail bean initialization (normally startup).
 * Class proxies cannot protect final methods/classes; JDK proxies can protect final
 * implementations when the method is exposed through an interface.
 * Self-invocation bypasses the proxy and is unsupported.
 * A method rule overrides a class rule.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RequiresRole {
    String[] value();
    boolean requireAll() default false;
}
