package com.autoauth.util;

import com.autoauth.annotation.PublicEndpoint;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import org.springframework.web.util.ServletRequestPathUtils;

/** Resolves the actual MVC handler, including its HTTP method and mapping conditions. */
public class EndpointScanner implements RequestMatcher {
    private final ApplicationContext context;
    public EndpointScanner(ApplicationContext context) { this.context = context; }

    @Override
    public boolean matches(HttpServletRequest request) {
        try {
            if (!ServletRequestPathUtils.hasParsedRequestPath(request)) ServletRequestPathUtils.parseAndCache(request);
            var mappings = context.getBean("requestMappingHandlerMapping", RequestMappingHandlerMapping.class);
            var chain = mappings.getHandler(request);
            return chain != null && chain.getHandler() instanceof HandlerMethod handler && isPublic(handler);
        } catch (Exception exception) {
            // Ambiguous/unsupported/unmapped requests never acquire public access.
            return false;
        }
    }

    public static boolean isPublic(HandlerMethod handler) {
        return AnnotatedElementUtils.hasAnnotation(handler.getMethod(), PublicEndpoint.class)
                || AnnotatedElementUtils.hasAnnotation(handler.getBeanType(), PublicEndpoint.class);
    }
}
