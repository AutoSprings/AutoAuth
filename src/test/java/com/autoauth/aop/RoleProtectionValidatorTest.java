package com.autoauth.aop;

import com.autoauth.annotation.RequiresRole;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import com.autoauth.model.AutoAuthUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RoleProtectionValidatorTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(JdkProxies.class);

    @AfterEach
    void clearAuthentication() { SecurityContextHolder.clearContext(); }

    @Test
    void rejectsEmptyAnyAndAllDeclarationsAtStartup() {
        assertInvalidDeclaration(EmptyAny.class, "at least one role", "admin");
        assertInvalidDeclaration(EmptyAll.class, "at least one role", "admin");
    }

    @Test
    void rejectsInvalidRoleNamesAtStartup() {
        for (Class<?> type : List.of(BlankRole.class, WhitespaceRole.class, BarePrefix.class, RepeatedPrefix.class)) {
            assertInvalidDeclaration(type, "role at index 0 is invalid", "admin");
        }
        assertInvalidDeclaration(MixedRoles.class, "role at index 1 is invalid", "admin");
    }

    @Test
    void validatesClassDeclarationsEvenWhenAllMethodsOverrideThem() {
        assertInvalidDeclaration(InvalidClassRule.class, "at least one role", "InvalidClassRule");
    }

    @Test
    void validatesInterfaceAndSuperclassDeclarations() {
        assertInvalidDeclaration(InvalidInterfaceService.class, "at least one role", "InvalidContract.admin");
        assertInvalidDeclaration(InvalidInheritedService.class, "role at index 0 is invalid", "InvalidBase.admin");
        assertInvalidDeclaration(InvalidInterfaceClassService.class, "at least one role", "InvalidClassContract");
    }

    @Test
    void acceptsValidRoleNamesAndKeepsExistingAuthorizationSemantics() {
        runner.withBean(ValidRoleNames.class).run(context -> {
            assertThat(context).hasNotFailed();
            ValidRoleNames service = context.getBean(ValidRoleNames.class);
            assertThatThrownBy(service::admin).isInstanceOf(AccessDeniedException.class);
            var user = new AutoAuthUser("alice", List.of("ADMIN", "team:read", "user"), null);
            SecurityContextHolder.getContext().setAuthentication(
                    new UsernamePasswordAuthenticationToken(user, null, List.of()));
            assertThat(service.admin()).isEqualTo("admin");
        });
    }

    private void assertInvalidDeclaration(Class<?> type, String reason, String declaration) {
        runner.withBean(type).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasStackTraceContaining("Invalid @RequiresRole")
                    .hasStackTraceContaining(declaration).hasStackTraceContaining(reason);
        });
    }

    @Test
    void rejectsPrivateAndFinalMvcHandlersBeforeServingRequests() {
        assertRejected(PrivateHandler.class, "private and static", "hidden");
        assertRejected(FinalHandler.class, "final methods/classes", "admin");
    }

    @Test
    void rejectsFinalProtectedClassesAndStaticDeclarations() {
        assertRejected(FinalService.class, "final methods/classes", "admin");
        assertRejected(StaticService.class, "private and static", "admin");
    }

    @Test
    void rejectsImplementationMethodsMissingFromJdkInterface() {
        assertRejected(ExtraMethodService.class, "not exposed by the JDK proxy", "admin");
    }

    @Test
    void classRuleAlsoRejectsUninterceptableCallableMethods() {
        assertRejected(ClassRuleHandler.class, "final methods/classes", "admin");
    }

    @Test
    void supportsFinalImplementationThroughJdkInterfaceAndActuallyDeniesAccess() {
        runner.withBean(FinalImplementation.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThatThrownBy(context.getBean(Contract.class)::admin).isInstanceOf(AccessDeniedException.class);
        });
    }

    @Test
    void supportsGenericInterfaceMethodsExposedThroughBridgeMethods() {
        runner.withBean(GenericService.class).run(context -> {
            assertThat(context).hasNotFailed();
            GenericContract<String> service = context.getBean(GenericContract.class);
            assertThatThrownBy(() -> service.admin("value")).isInstanceOf(AccessDeniedException.class);
        });
    }

    @Test
    void supportsClassProxyAndIgnoresPrivateHelpersUnderClassRule() {
        runner.withUserConfiguration(ClassProxies.class).withBean(ValidService.class).run(context -> {
            assertThat(context).hasNotFailed();
            assertThatThrownBy(context.getBean(ValidService.class)::admin).isInstanceOf(AccessDeniedException.class);
        });
    }

    @Test
    void forcedClassProxyRejectsFinalInterfaceImplementationClearly() {
        runner.withUserConfiguration(ClassProxies.class).withBean(FinalImplementation.class).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasStackTraceContaining("Cannot enforce @RequiresRole")
                    .hasStackTraceContaining("final methods/classes").hasStackTraceContaining("admin");
        });
    }

    @Test
    void rejectsProtectedBeanWithoutAutoProxying() {
        new ApplicationContextRunner().withUserConfiguration(ValidationOnly.class)
                .withBean(ValidService.class).run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasStackTraceContaining("no AutoAuth role advisor");
                });
    }

    private <T> void assertRejected(Class<T> type, String reason, String method) {
        runner.withBean(type).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).hasStackTraceContaining("Cannot enforce @RequiresRole")
                    .hasStackTraceContaining(type.getName()).hasStackTraceContaining(method)
                    .hasStackTraceContaining(reason);
        });
    }

    @Configuration(proxyBeanMethods = false)
    static class ValidationOnly {
        @Bean static RoleProtectionValidator validator(ConfigurableListableBeanFactory factory) {
            return new RoleProtectionValidator(factory);
        }
        @Bean RoleAspect roleAspect() { return new RoleAspect(); }
    }
    @Configuration(proxyBeanMethods = false)
    @EnableAspectJAutoProxy
    static class JdkProxies extends ValidationOnly {}
    @Configuration(proxyBeanMethods = false)
    @EnableAspectJAutoProxy(proxyTargetClass = true)
    static class ClassProxies {}

    @RestController
    public static class EmptyAny { @RequiresRole({}) public void admin() {} }
    public static class EmptyAll { @RequiresRole(value = {}, requireAll = true) public void admin() {} }
    public static class BlankRole { @RequiresRole("") public void admin() {} }
    public static class WhitespaceRole { @RequiresRole(" ADMIN ") public void admin() {} }
    public static class BarePrefix { @RequiresRole("ROLE_") public void admin() {} }
    public static class RepeatedPrefix { @RequiresRole("ROLE_ROLE_ADMIN") public void admin() {} }
    public static class MixedRoles { @RequiresRole({"ADMIN", " "}) public void admin() {} }
    @RequiresRole({})
    public static class InvalidClassRule { @RequiresRole("ADMIN") public void admin() {} }
    public interface InvalidContract { @RequiresRole({}) void admin(); }
    public static class InvalidInterfaceService implements InvalidContract {
        @RequiresRole("ADMIN") public void admin() {}
    }
    @RequiresRole({})
    public interface InvalidClassContract { void admin(); }
    public static class InvalidInterfaceClassService implements InvalidClassContract {
        @RequiresRole("ADMIN") public void admin() {}
    }
    public static class InvalidBase { @RequiresRole(" ") public void admin() {} }
    public static class InvalidInheritedService extends InvalidBase {
        @Override @RequiresRole("ADMIN") public void admin() {}
    }
    public static class ValidRoleNames {
        @RequiresRole(value = {"ROLE_ADMIN", "ADMIN", "team:read", "user"}, requireAll = true)
        public String admin() { return "admin"; }
    }

    @RestController
    public static class PrivateHandler {
        @RequiresRole("ADMIN") @GetMapping("/hidden") private String hidden() { return "hidden"; }
    }
    @RestController
    public static class FinalHandler {
        @RequiresRole("ADMIN") @GetMapping("/admin") public final String admin() { return "admin"; }
    }
    @RequiresRole("ADMIN") @RestController
    public static class ClassRuleHandler {
        @GetMapping("/admin") public final String admin() { return "admin"; }
    }
    public static final class FinalService {
        @RequiresRole("ADMIN") public String admin() { return "admin"; }
    }
    public static class StaticService {
        @RequiresRole("ADMIN") public static String admin() { return "admin"; }
    }
    public interface Contract {
        @RequiresRole("ADMIN") String admin();
    }
    public static final class FinalImplementation implements Contract {
        public final String admin() { return "admin"; }
    }
    public interface OtherContract { String open(); }
    public interface GenericContract<T> { T admin(T value); }
    public static class GenericService implements GenericContract<String> {
        @RequiresRole("ADMIN") public String admin(String value) { return value; }
    }
    public static class ExtraMethodService implements OtherContract {
        public String open() { return "open"; }
        @RequiresRole("ADMIN") public String admin() { return "admin"; }
    }
    @RequiresRole("ADMIN")
    public static class ValidService {
        public String admin() { return helper(); }
        private String helper() { return "admin"; }
    }
}
