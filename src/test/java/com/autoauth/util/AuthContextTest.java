package com.autoauth.util;

import com.autoauth.model.AutoAuthUser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AuthContextTest {
    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void returnsEmptyForMissingAuthentication() {
        assertThat(AuthContext.getCurrentUser()).isEmpty();
        assertThat(AuthContext.getCurrentUserId()).isEmpty();
        assertThat(AuthContext.getCurrentUserRoles()).isEmpty();
        assertThat(AuthContext.getCustomClaim("tenant")).isEmpty();
    }

    @Test
    void returnsEmptyForOtherPrincipalTypes() {
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken("anonymousUser", null));
        assertThat(AuthContext.getCurrentUser()).isEmpty();
    }

    @Test
    void exposesUserIdRolesAndCustomClaims() {
        AutoAuthUser user = new AutoAuthUser("alice", List.of("USER"), Map.of("tenant", "acme"));
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(user, null, List.of()));
        assertThat(AuthContext.getCurrentUser()).contains(user);
        assertThat(AuthContext.getCurrentUserId()).contains("alice");
        assertThat(AuthContext.getCurrentUserRoles()).contains(List.of("USER"));
        assertThat(AuthContext.getCustomClaim("tenant")).contains("acme");
        assertThat(AuthContext.getCustomClaim("missing")).isEmpty();
    }
}
