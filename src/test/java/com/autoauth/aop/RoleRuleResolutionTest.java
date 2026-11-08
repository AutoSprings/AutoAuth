package com.autoauth.aop;

import com.autoauth.annotation.RequiresRole;
import com.autoauth.config.AutoAuthSwaggerConfig;
import com.autoauth.model.AutoAuthUser;
import io.swagger.v3.oas.models.Operation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.method.HandlerMethod;

import java.util.List;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.annotation.ElementType;

import static org.assertj.core.api.Assertions.*;

class RoleRuleResolutionTest {
    @AfterEach
    void clearAuthentication() { SecurityContextHolder.clearContext(); }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void conflictingSiblingMethodsFailStartupRegardlessOfInterfaceOrder(boolean classProxy) {
        for (Class<?> type : List.of(Conflicting.class, ReversedConflict.class)) {
            runner(classProxy).withBean("service", type).run(context -> {
                assertThat(context).hasFailed();
                assertThat(context.getStartupFailure()).hasStackTraceContaining("service")
                        .hasStackTraceContaining("Conflicting @RequiresRole declarations")
                        .hasStackTraceContaining(Admin.class.getName()).hasStackTraceContaining(Auditor.class.getName())
                        .hasStackTraceContaining("admin");
            });
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void implementationMethodResolvesInterfaceConflictAndOverridesClassRule(boolean classProxy) {
        assertRole(classProxy, Explicit.class, "USER", "ADMIN");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void nearestClassMethodIsInheritedAndWinsOverClassAndInterfaceRules(boolean classProxy) {
        assertRole(classProxy, InheritedMethod.class, "USER", "ADMIN");
        assertRole(classProxy, OverriddenMethod.class, "EDITOR", "USER");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void mostSpecificInterfaceMethodOverridesParentAndClassRules(boolean classProxy) {
        assertRole(classProxy, ChildMethodService.class, "USER", "ADMIN");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void equivalentSiblingRulesAcceptNormalizedSetsRegardlessOfOrderAndDuplicates(boolean classProxy) {
        assertRole(classProxy, EquivalentService.class, "USER", "GUEST");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void differentAnyAllModesConflict(boolean classProxy) {
        runner(classProxy).withBean("service", ModeConflict.class).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasStackTraceContaining("Conflicting @RequiresRole declarations");
        });
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void nearestClassTypeRuleWinsWhenNoMethodRuleApplies(boolean classProxy) {
        assertRole(classProxy, ChildTypeService.class, "USER", "ADMIN");
        assertRole(classProxy, InheritedTypeService.class, "ADMIN", "USER");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void interfaceTypeConflictsFailUnlessClassTypeResolvesThem(boolean classProxy) {
        runner(classProxy).withBean("service", TypeConflict.class).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasStackTraceContaining("Conflicting @RequiresRole declarations")
                    .hasStackTraceContaining(AdminType.class.getName()).hasStackTraceContaining(AuditorType.class.getName());
        });
        assertRole(classProxy, ExplicitType.class, "USER", "ADMIN");
        assertRole(classProxy, ChildInterfaceTypeService.class, "USER", "ADMIN");
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void composedMethodRulesKeepImplementationPrecedence(boolean classProxy) {
        assertRole(classProxy, ComposedService.class, "USER", "ADMIN");
    }

    @Test
    void composedDeclarationsAlsoReceiveStartupValueValidation() {
        runner(false).withBean("service", InvalidComposedService.class).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasStackTraceContaining("Invalid @RequiresRole")
                    .hasStackTraceContaining("at least one role");
        });
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void genericInterfaceAndImplementationRulesResolveThroughBridgeMethods(boolean classProxy) {
        for (Class<?> type : List.of(GenericService.class, ExplicitGenericService.class)) {
            runner(classProxy).withBean("service", type).run(context -> {
                assertThat(context).hasNotFailed();
                @SuppressWarnings("unchecked")
                Generic<String> service = (Generic<String>) context.getBean("service");
                authenticate(type == GenericService.class ? "USER" : "ADMIN");
                assertThatThrownBy(() -> service.admin("result")).isInstanceOf(AccessDeniedException.class);
                authenticate(type == GenericService.class ? "ADMIN" : "USER");
                assertThat(service.admin("result")).isEqualTo("result");
            });
        }
    }

    @Test
    void interfaceTypeRuleOnlyAppliesToThatInterfaceContract() throws Exception {
        assertThat(RoleRuleResolver.resolve(UnrelatedMethod.class.getMethod("open"), UnrelatedMethod.class)).isNull();
        assertThat(RoleRuleResolver.resolve(UnrelatedMethod.class.getMethod("admin"), UnrelatedMethod.class)).isNotNull();
    }

    @Test
    void swaggerUsesTheSameInheritedInterfaceRuleAsEnforcement() throws Exception {
        var handler = new HandlerMethod(new ChildMethodService(), ChildMethodService.class.getMethod("admin"));
        Operation operation = new AutoAuthSwaggerConfig().autoAuthOperationSecurity().customize(new Operation(), handler);
        assertThat(operation.getExtensions()).containsEntry("x-autoauth-roles", List.of("USER"))
                .containsEntry("x-autoauth-require-all", false);
    }

    private ApplicationContextRunner runner(boolean classProxy) {
        var runner = new ApplicationContextRunner().withUserConfiguration(RoleProtectionValidatorTest.JdkProxies.class);
        return classProxy ? runner.withUserConfiguration(RoleProtectionValidatorTest.ClassProxies.class) : runner;
    }

    private void assertRole(boolean classProxy, Class<?> type, String allowed, String denied) {
        runner(classProxy).withBean("service", type).run(context -> {
            assertThat(context).hasNotFailed();
            Route service = (Route) context.getBean("service");
            SecurityContextHolder.clearContext();
            assertThatThrownBy(service::admin).isInstanceOf(AccessDeniedException.class);
            authenticate(denied);
            assertThatThrownBy(service::admin).isInstanceOf(AccessDeniedException.class);
            authenticate(allowed);
            assertThat(service.admin()).isEqualTo("admin");
        });
    }

    private void authenticate(String role) {
        var user = new AutoAuthUser("alice", List.of(role), null);
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(user, null, List.of()));
    }

    public interface Route { String admin(); }
    public interface Admin extends Route { @RequiresRole("ADMIN") String admin(); }
    public interface Auditor extends Route { @RequiresRole("AUDITOR") String admin(); }
    public static class Conflicting implements Admin, Auditor { public String admin() { return "admin"; } }
    public static class ReversedConflict implements Auditor, Admin { public String admin() { return "admin"; } }
    @RequiresRole("EDITOR")
    public static class Explicit implements Admin, Auditor {
        @RequiresRole("USER") public String admin() { return "admin"; }
    }
    public static class BaseMethod implements Route {
        @RequiresRole("USER") public String admin() { return "admin"; }
    }
    @RequiresRole("AUDITOR")
    public static class InheritedMethod extends BaseMethod implements Admin {
        @Override public String admin() { return "admin"; }
    }
    public static class OverriddenMethod extends BaseMethod implements Admin {
        @Override @RequiresRole("EDITOR") public String admin() { return "admin"; }
    }
    public interface ChildMethod extends Admin { @RequiresRole("USER") String admin(); }
    @RequiresRole("AUDITOR")
    public static class ChildMethodService implements ChildMethod { public String admin() { return "admin"; } }
    public interface EquivalentA extends Route { @RequiresRole({"ROLE_ADMIN", "USER"}) String admin(); }
    public interface EquivalentB extends Route { @RequiresRole({"USER", "ADMIN", "ADMIN"}) String admin(); }
    public static class EquivalentService implements EquivalentA, EquivalentB { public String admin() { return "admin"; } }
    public interface AllRoles extends Route { @RequiresRole(value = {"ADMIN", "USER"}, requireAll = true) String admin(); }
    public static class ModeConflict implements EquivalentA, AllRoles { public String admin() { return "admin"; } }
    @RequiresRole("ADMIN")
    public static class BaseType implements Route { public String admin() { return "admin"; } }
    @RequiresRole("USER")
    public static class ChildTypeService extends BaseType {}
    public static class InheritedTypeService extends BaseType {}
    @RequiresRole("ADMIN") public interface AdminType extends Route {}
    @RequiresRole("AUDITOR") public interface AuditorType extends Route {}
    public static class TypeConflict implements AdminType, AuditorType { public String admin() { return "admin"; } }
    @RequiresRole("USER") public static class ExplicitType extends TypeConflict {}
    @RequiresRole("USER") public interface ChildInterfaceType extends AdminType {}
    public static class ChildInterfaceTypeService implements ChildInterfaceType { public String admin() { return "admin"; } }
    public static class UnrelatedMethod implements AdminType {
        public String admin() { return "admin"; }
        public String open() { return "open"; }
    }
    public interface Generic<T> { @RequiresRole("ADMIN") T admin(T value); }
    public static class GenericService implements Generic<String> { public String admin(String value) { return value; } }
    public static class ExplicitGenericService implements Generic<String> {
        @RequiresRole("USER") public String admin(String value) { return value; }
    }
    @RequiresRole("USER") @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
    public @interface UserRole {}
    public static class ComposedService implements Admin, Auditor {
        @UserRole public String admin() { return "admin"; }
    }
    @RequiresRole({}) @Retention(RetentionPolicy.RUNTIME) @Target(ElementType.METHOD)
    public @interface EmptyRole {}
    public static class InvalidComposedService implements Route {
        @EmptyRole public String admin() { return "admin"; }
    }
}
