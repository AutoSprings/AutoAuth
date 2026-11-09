package com.autoauth.model;

/**
 * Independently signed access and refresh credentials. Creating a pair does not
 * revoke previous tokens or establish a managed refresh session.
 *
 * @param accessToken access-purpose JWT containing current roles and custom claims
 * @param refreshToken refresh-purpose JWT; the application validates it and reloads account data
 */
public record TokenPair(
        String accessToken,
        String refreshToken
) {}
