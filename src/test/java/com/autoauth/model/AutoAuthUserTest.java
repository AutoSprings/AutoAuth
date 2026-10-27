package com.autoauth.model;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AutoAuthUserTest {
    @Test
    void missingRolesAndClaimsDefaultToEmptyCollections() {
        AutoAuthUser user = new AutoAuthUser("alice", null, null);
        assertThat(user.userId()).isEqualTo("alice");
        assertThat(user.roles()).isEmpty();
        assertThat(user.customClaims()).isEmpty();
    }
}
