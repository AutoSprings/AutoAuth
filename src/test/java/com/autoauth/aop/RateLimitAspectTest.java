package com.autoauth.aop;

import com.autoauth.annotation.RateLimit;
import com.autoauth.annotation.UserQuota;
import com.autoauth.exception.RateLimitExceededException;
import com.autoauth.model.AutoAuthUser;
import com.autoauth.ratelimit.RateLimitService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.aop.aspectj.annotation.AspectJProxyFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class RateLimitAspectTest {
    private final RateLimitService limiter = mock(RateLimitService.class);
    private LimitedService service;

    @BeforeEach
    void setUp() {
        AspectJProxyFactory factory = new AspectJProxyFactory(new LimitedService());
        factory.addAspect(new RateLimitAspect(limiter));
        service = factory.getProxy();
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void choosesHighestMatchingRoleQuotaCaseInsensitively() {
        authenticate("premium", "ENTERPRISE");
        when(limiter.isAllowed("user:alice:tiered", 20, 30_000)).thenReturn(true);
        assertThat(service.tiered()).isEqualTo("ok");
        verify(limiter).isAllowed("user:alice:tiered", 20, 30_000);
    }

    @Test
    void unmatchedRolesUseFallbackQuota() {
        authenticate("USER");
        when(limiter.isAllowed("user:alice:tiered", 2, 30_000)).thenReturn(true);
        service.tiered();
        verify(limiter).isAllowed("user:alice:tiered", 2, 30_000);
    }

    @Test
    void anonymousRequestsUseFirstForwardedIp() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("X-Forwarded-For", "203.0.113.10, 10.0.0.1");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        when(limiter.isAllowed("ip:203.0.113.10:tiered", 2, 30_000)).thenReturn(true);
        service.tiered();
        verify(limiter).isAllowed("ip:203.0.113.10:tiered", 2, 30_000);
    }

    @Test
    void anonymousRequestsFallBackToRemoteAddress() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("203.0.113.11");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        when(limiter.isAllowed("ip:203.0.113.11:tiered", 2, 30_000)).thenReturn(true);
        service.tiered();
        verify(limiter).isAllowed("ip:203.0.113.11:tiered", 2, 30_000);
    }

    @Test
    void exceededQuotaPreventsMethodInvocation() {
        assertThatThrownBy(service::tiered).isInstanceOf(RateLimitExceededException.class);
        verify(limiter).isAllowed("ip:unknown:tiered", 2, 30_000);
    }

    @Test
    void classLimitAppliesUnlessMethodOverridesIt() {
        when(limiter.isAllowed("ip:unknown:classLimited", 3, 60_000)).thenReturn(true);
        when(limiter.isAllowed("ip:unknown:override", 1, 60_000)).thenReturn(true);
        service.classLimited();
        service.override();
        verify(limiter).isAllowed("ip:unknown:classLimited", 3, 60_000);
        verify(limiter).isAllowed("ip:unknown:override", 1, 60_000);
    }

    private void authenticate(String... roles) {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(
                new AutoAuthUser("alice", List.of(roles), null), null, List.of()));
    }

    @RateLimit(fallbackRequests = 3)
    public static class LimitedService {
        @RateLimit(value = {@UserQuota(role = "PREMIUM", maxRequests = 10),
                @UserQuota(role = "ENTERPRISE", maxRequests = 20)},
                fallbackRequests = 2, window = 30, unit = TimeUnit.SECONDS)
        public String tiered() { return "ok"; }
        public void classLimited() {}
        @RateLimit(fallbackRequests = 1) public void override() {}
    }
}
