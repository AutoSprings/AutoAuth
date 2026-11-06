package com.autoauth.util;

import com.autoauth.annotation.PublicEndpoint;
import org.junit.jupiter.api.Test;
import org.springframework.web.method.HandlerMethod;
import static org.assertj.core.api.Assertions.*;

class EndpointScannerTest {
    @Test void detectsInheritedPublicMethodsAndClassAnnotations() throws Exception {
        assertThat(EndpointScanner.isPublic(new HandlerMethod(new Child(), Child.class.getMethod("publicMethod")))).isTrue();
        assertThat(EndpointScanner.isPublic(new HandlerMethod(new PublicClass(), PublicClass.class.getMethod("handler")))).isTrue();
        assertThat(EndpointScanner.isPublic(new HandlerMethod(new Child(), Child.class.getMethod("privateMethod")))).isFalse();
    }
    public static class Parent { @PublicEndpoint public void publicMethod() {} }
    public static class Child extends Parent { public void privateMethod() {} }
    @PublicEndpoint public static class PublicClass { public void handler() {} }
}
