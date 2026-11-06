package com.autoauth.annotation;

import java.lang.annotation.*;

/**
 * Allows anonymous access to this MVC handler, or the registered handlers of this controller.
 * HTTP method and mapping conditions are preserved. Cookie-mode CSRF protection still applies.
 * An explicitly supplied invalid JWT is rejected even on a public endpoint.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface PublicEndpoint {}
