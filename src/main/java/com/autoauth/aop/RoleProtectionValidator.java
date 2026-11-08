package com.autoauth.aop;

import com.autoauth.annotation.RequiresRole;
import org.springframework.aop.config.AopConfigUtils;
import org.springframework.aop.framework.Advised;
import org.springframework.aop.framework.ProxyConfig;
import org.springframework.aop.framework.autoproxy.AutoProxyUtils;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.BridgeMethodResolver;
import org.springframework.util.ClassUtils;
import org.springframework.util.ReflectionUtils;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Arrays;

/** Rejects role declarations that Spring's configured proxy cannot enforce. */
public final class RoleProtectionValidator implements BeanPostProcessor {
    private final ConfigurableListableBeanFactory beanFactory;
    private final RoleAspect rules = new RoleAspect();

    public RoleProtectionValidator(ConfigurableListableBeanFactory beanFactory) {
        this.beanFactory = beanFactory;
    }

    @Override
    public Object postProcessBeforeInitialization(Object bean, String beanName) {
        Class<?> targetClass = AopUtils.getTargetClass(bean);
        boolean classProxy = usesClassProxy(targetClass, beanName);
        for (Method method : ReflectionUtils.getAllDeclaredMethods(targetClass)) {
            if (!requiresProtection(method, targetClass)) continue;
            int modifiers = method.getModifiers();
            if (Modifier.isPrivate(modifiers) || Modifier.isStatic(modifiers)) {
                throw failure(beanName, method, "private and static methods cannot be intercepted by Spring proxies");
            }
            if (classProxy && (Modifier.isFinal(modifiers) || Modifier.isFinal(targetClass.getModifiers()))) {
                throw failure(beanName, method, "final methods/classes cannot be intercepted by a class proxy; "
                        + "remove final or expose the protected method through a JDK interface proxy");
            }
            if (classProxy && !Modifier.isPublic(modifiers) && !Modifier.isProtected(modifiers)
                    && !ClassUtils.getPackageName(method.getDeclaringClass()).equals(ClassUtils.getPackageName(targetClass))) {
                throw failure(beanName, method, "an inherited package-private method in another package cannot be intercepted");
            }
        }
        return bean;
    }

    @Override
    public Object postProcessAfterInitialization(Object bean, String beanName) {
        Class<?> targetClass = AopUtils.getTargetClass(bean);
        for (Method method : ReflectionUtils.getAllDeclaredMethods(targetClass)) {
            if (!requiresProtection(method, targetClass)) continue;
            if (AopUtils.isCglibProxy(bean) && Modifier.isFinal(method.getModifiers())) {
                throw failure(beanName, method, "final methods cannot be intercepted by the actual class proxy");
            }
            if (!(bean instanceof Advised advised) || Arrays.stream(advised.getAdvisors())
                    .noneMatch(advisor -> advisor instanceof RoleAspect role && role.matches(method, targetClass))) {
                throw failure(beanName, method, "no AutoAuth role advisor protects this bean");
            }
            if (AopUtils.isJdkDynamicProxy(bean)) {
                boolean exposed = Arrays.stream(advised.getProxiedInterfaces())
                        .flatMap(contract -> Arrays.stream(contract.getMethods())).anyMatch(proxyMethod ->
                        BridgeMethodResolver.findBridgedMethod(AopUtils.getMostSpecificMethod(proxyMethod, targetClass))
                                .equals(method));
                if (!exposed) {
                    throw failure(beanName, method, "the protected method is not exposed by the JDK proxy; "
                            + "add it to an interface or use a class proxy");
                }
            }
        }
        return bean;
    }

    private boolean requiresProtection(Method method, Class<?> targetClass) {
        if (method.getDeclaringClass() == Object.class || method.isBridge() || method.isSynthetic()) return false;
        boolean explicit = AnnotatedElementUtils.hasAnnotation(method, RequiresRole.class);
        // A class rule protects callable methods, not private/static implementation helpers.
        if (!explicit && (Modifier.isPrivate(method.getModifiers()) || Modifier.isStatic(method.getModifiers()))) return false;
        return rules.matches(method, targetClass);
    }

    private boolean usesClassProxy(Class<?> targetClass, String beanName) {
        if (AutoProxyUtils.shouldProxyTargetClass(beanFactory, beanName)) return true;
        if (beanFactory.containsBean(AopConfigUtils.AUTO_PROXY_CREATOR_BEAN_NAME)
                && beanFactory.getBean(AopConfigUtils.AUTO_PROXY_CREATOR_BEAN_NAME) instanceof ProxyConfig config
                && config.isProxyTargetClass()) return true;
        return ClassUtils.getAllInterfacesForClass(targetClass).length == 0;
    }

    private BeanCreationException failure(String beanName, Method method, String reason) {
        return new BeanCreationException(beanName, "Cannot enforce @RequiresRole on "
                + method.toGenericString() + ": " + reason);
    }
}
