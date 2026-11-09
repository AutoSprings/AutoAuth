package com.autoauth.model;

import java.util.List;
import java.util.Map;

/**
 * Trusted identity provided by an application or extracted from a validated token.
 * Roles are normalized and immutable. Custom claims are copied shallowly; nested
 * values should be immutable and must remain within token and cookie size budgets.
 *
 * @param userId nonblank application-owned account identifier
 * @param roles case-sensitive roles; null means no roles; one ROLE_ prefix is removed
 * @param customClaims additional access-token claims; null means no claims
 */
public record AutoAuthUser(String userId, List<String> roles, Map<String, Object> customClaims) {
    public AutoAuthUser {
        if (userId == null || userId.isBlank()) throw new IllegalArgumentException("userId must not be blank");
        roles = roles == null ? List.of() : roles.stream().map(AutoAuthUser::canonicalRole).distinct().toList();
        if (customClaims != null && customClaims.entrySet().stream()
                .anyMatch(entry -> entry.getKey() == null || entry.getValue() == null)) {
            throw new IllegalArgumentException("Custom claims must not contain null keys or values");
        }
        customClaims = customClaims == null ? Map.of() : Map.copyOf(customClaims);
    }

    /** Role names are case-sensitive; an optional Spring ROLE_ prefix is removed once. */
    public static String canonicalRole(String role) {
        if (role == null || role.isBlank() || !role.equals(role.trim())) {
            throw new IllegalArgumentException("Roles must not be blank or contain surrounding whitespace");
        }
        String canonical = role.startsWith("ROLE_") ? role.substring(5) : role;
        if (canonical.isBlank() || canonical.startsWith("ROLE_")) {
            throw new IllegalArgumentException("Invalid role name");
        }
        return canonical;
    }
}
