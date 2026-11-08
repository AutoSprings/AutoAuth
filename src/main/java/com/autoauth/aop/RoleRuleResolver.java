package com.autoauth.aop;

import com.autoauth.annotation.RequiresRole;
import com.autoauth.model.AutoAuthUser;
import org.springframework.aop.support.AopUtils;
import org.springframework.core.BridgeMethodResolver;
import org.springframework.core.annotation.MergedAnnotations;
import org.springframework.util.ClassUtils;

import java.lang.reflect.Method;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/** Shared role resolution for proxy enforcement, startup validation, and API metadata. */
public final class RoleRuleResolver {
    private RoleRuleResolver() {}

    /**
     * Resolves class-hierarchy method rules, interface method rules, class-hierarchy
     * type rules, then interface type rules, in that order. The nearest annotated
     * class declaration or most specific annotated interface declaration wins.
     * Unrelated interfaces must agree on normalized role sets and requireAll.
     *
     * @param method the invoked or mapped method, including interface/bridge methods
     * @param targetClass the implementation class
     * @return the effective declaration, or null if no role rule applies
     * @throws IllegalStateException if equally specific interface rules conflict
     */
    public static RequiresRole resolve(Method method, Class<?> targetClass) {
        targetClass = ClassUtils.getUserClass(targetClass);
        Method specific = specificMethod(method, targetClass);
        for (Class<?> type = targetClass; type != null && type != Object.class; type = type.getSuperclass()) {
            for (Method candidate : type.getDeclaredMethods()) {
                RequiresRole rule = declaredRule(candidate);
                if (rule != null && !candidate.isBridge() && !candidate.isSynthetic()
                        && specificMethod(candidate, targetClass).equals(specific)) return rule;
            }
        }

        Set<Class<?>> contracts = ClassUtils.getAllInterfacesForClassAsSet(targetClass);
        List<Declaration> methodRules = new ArrayList<>();
        for (Class<?> contract : contracts) {
            for (Method candidate : contract.getDeclaredMethods()) {
                RequiresRole rule = declaredRule(candidate);
                if (rule != null && isInterfaceMethod(candidate)
                        && specificMethod(candidate, targetClass).equals(specific)) {
                    methodRules.add(new Declaration(contract, rule));
                }
            }
        }
        RequiresRole rule = interfaceRule(methodRules, specific, targetClass);
        if (rule != null) return rule;

        for (Class<?> type = targetClass; type != null && type != Object.class; type = type.getSuperclass()) {
            rule = declaredRule(type);
            if (rule != null) return rule;
        }

        List<Declaration> typeRules = new ArrayList<>();
        for (Class<?> contract : contracts) {
            rule = declaredRule(contract);
            if (rule == null) continue;
            for (Method candidate : contract.getMethods()) {
                if (isInterfaceMethod(candidate) && specificMethod(candidate, targetClass).equals(specific)) {
                    typeRules.add(new Declaration(contract, rule));
                    break;
                }
            }
        }
        return interfaceRule(typeRules, specific, targetClass);
    }

    private static Method specificMethod(Method method, Class<?> targetClass) {
        return BridgeMethodResolver.findBridgedMethod(AopUtils.getMostSpecificMethod(method, targetClass));
    }

    static RequiresRole declaredRule(AnnotatedElement element) {
        var annotation = MergedAnnotations.from(element, MergedAnnotations.SearchStrategy.DIRECT).get(RequiresRole.class);
        return annotation.isPresent() ? annotation.synthesize() : null;
    }

    private static boolean isInterfaceMethod(Method method) {
        return !method.isBridge() && !method.isSynthetic()
                && !Modifier.isStatic(method.getModifiers()) && !Modifier.isPrivate(method.getModifiers());
    }

    private static RequiresRole interfaceRule(List<Declaration> declarations, Method method, Class<?> targetClass) {
        List<Declaration> mostSpecific = declarations.stream()
                .filter(candidate -> declarations.stream().noneMatch(other -> candidate.owner() != other.owner()
                        && candidate.owner().isAssignableFrom(other.owner())))
                .sorted(Comparator.comparing(declaration -> declaration.owner().getName())).toList();
        if (mostSpecific.isEmpty()) return null;
        RequiresRole selected = mostSpecific.getFirst().rule();
        for (Declaration declaration : mostSpecific) {
            if (selected.requireAll() != declaration.rule().requireAll()
                    || !normalizedRoles(selected).equals(normalizedRoles(declaration.rule()))) {
                throw new IllegalStateException("Conflicting @RequiresRole declarations for " + targetClass.getName()
                        + " method " + method.toGenericString() + " on interfaces "
                        + mostSpecific.stream().map(candidate -> candidate.owner().getName()).toList()
                        + "; add an explicit implementation method rule to resolve the conflict");
            }
        }
        return selected;
    }

    private static Set<String> normalizedRoles(RequiresRole rule) {
        return new TreeSet<>(Arrays.stream(rule.value()).map(AutoAuthUser::canonicalRole).toList());
    }

    private record Declaration(Class<?> owner, RequiresRole rule) {}
}
