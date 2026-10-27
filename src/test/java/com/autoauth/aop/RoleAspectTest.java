package com.autoauth.aop;

import com.autoauth.annotation.RequiresRole;
import com.autoauth.model.AutoAuthUser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.aop.aspectj.annotation.AspectJProxyFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;

import static org.assertj.core.api.Assertions.*;

class RoleAspectTest {
    private final SecuredService service = proxy(new SecuredService());

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void deniesAnonymousUsersAndUsersWithWrongRole() {
        assertThatThrownBy(service::anyRole).isInstanceOf(AccessDeniedException.class);
        authenticate("GUEST");
        assertThatThrownBy(service::anyRole).isInstanceOf(AccessDeniedException.class);
    }

    @Test
    void anyMatchingRoleAllowsInvocation() {
        authenticate("USER");
        assertThat(service.anyRole()).isEqualTo("allowed");
    }

    @Test
    void requireAllRejectsPartialMatches() {
        authenticate("ADMIN");
        assertThatThrownBy(service::allRoles).isInstanceOf(AccessDeniedException.class);
        authenticate("ADMIN", "USER");
        assertThat(service.allRoles()).isEqualTo("allowed");
    }

    @Test
    void classAnnotationAppliesAndMethodAnnotationOverridesIt() {
        ClassSecuredService classService = proxy(new ClassSecuredService());
        authenticate("USER");
        assertThatThrownBy(classService::admin).isInstanceOf(AccessDeniedException.class);
        assertThat(classService.user()).isEqualTo("user");
        authenticate("ADMIN");
        assertThat(classService.admin()).isEqualTo("admin");
    }

    private static <T> T proxy(T target) {
        AspectJProxyFactory factory = new AspectJProxyFactory(target);
        factory.addAspect(new RoleAspect());
        return factory.getProxy();
    }

    private void authenticate(String... roles) {
        var user = new AutoAuthUser("alice", List.of(roles), null);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(user, null, List.of()));
    }

    public static class SecuredService {
        @RequiresRole({"ADMIN", "USER"}) public String anyRole() { return "allowed"; }
        @RequiresRole(value = {"ADMIN", "USER"}, requireAll = true)
        public String allRoles() { return "allowed"; }
    }

    @RequiresRole("ADMIN")
    public static class ClassSecuredService {
        public String admin() { return "admin"; }
        @RequiresRole("USER") public String user() { return "user"; }
    }
}
