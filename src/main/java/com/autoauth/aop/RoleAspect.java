package com.autoauth.aop;

import com.autoauth.annotation.RequiresRole;
import com.autoauth.model.AutoAuthUser;
import com.autoauth.util.AuthContext;
import org.aopalliance.intercept.*;
import org.springframework.aop.support.AopUtils;
import org.springframework.aop.support.StaticMethodMatcherPointcutAdvisor;
import org.springframework.core.BridgeMethodResolver;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.util.ClassUtils;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

/** Proxy-based role enforcement with method rules overriding class rules. */
public class RoleAspect extends StaticMethodMatcherPointcutAdvisor implements MethodInterceptor {
    public RoleAspect() { setAdvice(this); }

    @Override
    public boolean matches(Method method, Class<?> targetClass) { return requirement(method, targetClass) != null; }

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        Class<?> targetClass = AopUtils.getTargetClass(invocation.getThis());
        RequiresRole rule = requirement(invocation.getMethod(), targetClass);
        if (rule != null) {
            if (rule.value().length == 0) throw new AccessDeniedException("Empty role requirement");
            List<String> required;
            try {
                required = Arrays.stream(rule.value()).map(AutoAuthUser::canonicalRole).toList();
            } catch (IllegalArgumentException exception) {
                throw new AccessDeniedException("Invalid role requirement", exception);
            }
            List<String> actual = AuthContext.getCurrentUser().map(AutoAuthUser::roles).orElse(List.of());
            boolean allowed = rule.requireAll() ? actual.containsAll(required) : required.stream().anyMatch(actual::contains);
            if (!allowed) throw new AccessDeniedException("Required role is missing");
        }
        return invocation.proceed();
    }

    private RequiresRole requirement(Method method, Class<?> targetClass) {
        Method specific = BridgeMethodResolver.findBridgedMethod(AopUtils.getMostSpecificMethod(method, targetClass));
        RequiresRole rule = AnnotatedElementUtils.findMergedAnnotation(specific, RequiresRole.class);
        if (rule == null) rule = AnnotatedElementUtils.findMergedAnnotation(method, RequiresRole.class);
        if (rule == null) {
            for (Class<?> contract : ClassUtils.getAllInterfacesForClassAsSet(targetClass)) {
                try {
                    rule = AnnotatedElementUtils.findMergedAnnotation(
                            contract.getMethod(method.getName(), method.getParameterTypes()), RequiresRole.class);
                    if (rule != null) break;
                } catch (NoSuchMethodException ignored) {
                    // This interface does not declare the intercepted method.
                }
            }
        }
        return rule != null ? rule : AnnotatedElementUtils.findMergedAnnotation(targetClass, RequiresRole.class);
    }
}
