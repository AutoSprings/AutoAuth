package com.autoauth.aop;

import com.autoauth.annotation.RequiresRole;
import com.autoauth.model.AutoAuthUser;
import com.autoauth.util.AuthContext;
import org.aopalliance.intercept.*;
import org.springframework.aop.support.AopUtils;
import org.springframework.aop.support.StaticMethodMatcherPointcutAdvisor;
import org.springframework.security.access.AccessDeniedException;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

/** Proxy-based role enforcement with method rules overriding class rules. */
public class RoleAspect extends StaticMethodMatcherPointcutAdvisor implements MethodInterceptor {
    public RoleAspect() { setAdvice(this); }

    @Override
    public boolean matches(Method method, Class<?> targetClass) { return RoleRuleResolver.resolve(method, targetClass) != null; }

    @Override
    public Object invoke(MethodInvocation invocation) throws Throwable {
        Class<?> targetClass = AopUtils.getTargetClass(invocation.getThis());
        RequiresRole rule = RoleRuleResolver.resolve(invocation.getMethod(), targetClass);
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

}
