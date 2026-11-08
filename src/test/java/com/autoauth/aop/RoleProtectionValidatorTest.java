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
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RoleProtectionValidatorTest {
    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(JdkProxies.class);

    @AfterEach
    void clearAuthentication() { SecurityContextHolder.clearContext(); }

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
