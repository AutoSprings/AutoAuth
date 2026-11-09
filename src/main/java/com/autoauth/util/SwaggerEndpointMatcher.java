package com.autoauth.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springdoc.webmvc.ui.SwaggerResourceResolver;
import org.springframework.context.ApplicationContext;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerMapping;
import org.springframework.web.servlet.resource.ResourceHttpRequestHandler;
import org.springframework.web.util.ServletRequestPathUtils;

/** Permits only registered springdoc GET handlers and its dedicated UI resources. */
public final class SwaggerEndpointMatcher implements RequestMatcher {
    private final ApplicationContext context;

    public SwaggerEndpointMatcher(ApplicationContext context) { this.context = context; }

    @Override
    public boolean matches(HttpServletRequest request) {
        if (!"GET".equals(request.getMethod())) return false;
        try {
            // A redispatch may carry the parsed path of the original public handler.
            ServletRequestPathUtils.parseAndCache(request);
            var mvc = context.getBean("requestMappingHandlerMapping", HandlerMapping.class).getHandler(request);
            if (mvc != null && mvc.getHandler() instanceof HandlerMethod handler) {
                return handler.getBeanType().getPackageName().startsWith("org.springdoc.webmvc.");
            }
            if (!context.containsBean("resourceHandlerMapping")) return false;
            var resources = context.getBean("resourceHandlerMapping", HandlerMapping.class).getHandler(request);
            return resources != null && resources.getHandler() instanceof ResourceHttpRequestHandler handler
                    && handler.getResourceResolvers().stream().anyMatch(SwaggerResourceResolver.class::isInstance);
        } catch (Exception exception) {
            // Missing, ambiguous, or unsupported handlers do not acquire public access.
            return false;
        }
    }
}
