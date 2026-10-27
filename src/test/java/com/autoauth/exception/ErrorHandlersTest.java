package com.autoauth.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;

import static org.assertj.core.api.Assertions.assertThat;

class ErrorHandlersTest {
    private final MockHttpServletRequest request = new MockHttpServletRequest();
    private final MockHttpServletResponse response = new MockHttpServletResponse();
    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void unauthenticatedRequestsReturnJson401() throws Exception {
        new AutoAuthAuthenticationEntryPoint().commence(request, response, new BadCredentialsException("invalid"));
        assertError(401, "Unauthorized");
    }

    @Test
    void forbiddenRequestsReturnJson403() throws Exception {
        new AutoAuthAccessDeniedHandler().handle(request, response, new AccessDeniedException("denied"));
        assertError(403, "Forbidden");
    }

    @Test
    void rateLimitResolverHandlesQuotaFailuresWithJson429() throws Exception {
        var result = new AutoAuthRateLimitExceptionResolver().resolveException(
                request, response, null, new RateLimitExceededException("exceeded"));
        assertThat(result).isNotNull();
        assertThat(result.isEmpty()).isTrue();
        assertError(429, "Too Many Requests");
    }

    @Test
    void rateLimitResolverLeavesOtherExceptionsForOtherResolvers() {
        var result = new AutoAuthRateLimitExceptionResolver().resolveException(
                request, response, null, new IllegalStateException("other"));
        assertThat(result).isNull();
        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(response.getContentAsByteArray()).isEmpty();
    }

    private void assertError(int status, String error) throws Exception {
        assertThat(response.getStatus()).isEqualTo(status);
        assertThat(response.getContentType()).isEqualTo("application/json");
        var body = mapper.readTree(response.getContentAsString());
        assertThat(body.get("error").asText()).isEqualTo(error);
        assertThat(body.get("message").asText()).isNotBlank();
    }
}
