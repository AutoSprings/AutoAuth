package com.autoauth.model;

import org.junit.jupiter.api.Test;
import java.util.*;
import static org.assertj.core.api.Assertions.*;

class AutoAuthUserTest {
    @Test void defaultsNullCollectionsAndRejectsBlankIdentity() {
        assertThat(new AutoAuthUser("alice", null, null).roles()).isEmpty();
        assertThatThrownBy(() -> new AutoAuthUser(" ", null, null)).isInstanceOf(IllegalArgumentException.class);
        var invalidClaims = new HashMap<String, Object>();
        invalidClaims.put("tenant", null);
        assertThatThrownBy(() -> new AutoAuthUser("alice", null, invalidClaims)).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void snapshotsRolesAndClaimsAndNormalizesPrefix() {
        var roles = new ArrayList<>(List.of("ROLE_ADMIN"));
        var claims = new HashMap<String, Object>(Map.of("tenant", "acme"));
        var user = new AutoAuthUser("alice", roles, claims);
        roles.clear();
        claims.clear();
        assertThat(user.roles()).containsExactly("ADMIN");
        assertThat(user.customClaims()).containsEntry("tenant", "acme");
        assertThatThrownBy(() -> user.roles().add("USER")).isInstanceOf(UnsupportedOperationException.class);
    }
}
