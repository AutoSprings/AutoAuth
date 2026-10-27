package com.autoauth.blacklist;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

class CafeTokenBlackListTest {
    private final CafeTokenBlackList blacklist = new CafeTokenBlackList();

    @Test
    void revokesOnlyTheSpecifiedToken() {
        blacklist.add("revoked", Duration.ofMinutes(1));
        assertThat(blacklist.isBlackListed("revoked")).isTrue();
        assertThat(blacklist.isBlackListed("other")).isFalse();
        assertThat(blacklist.isUserBanned("revoked")).isFalse();
    }

    @Test
    void bansAndUnbansUsersIndependentlyOfTokens() {
        blacklist.banUser("user", Duration.ofMinutes(1));
        assertThat(blacklist.isUserBanned("user")).isTrue();
        assertThat(blacklist.isBlackListed("user")).isFalse();
        blacklist.unbanUser("user");
        assertThat(blacklist.isUserBanned("user")).isFalse();
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = " ")
    void ignoresInvalidIdentifiers(String id) {
        blacklist.add(id, Duration.ofMinutes(1));
        blacklist.banUser(id, Duration.ofMinutes(1));
        blacklist.unbanUser(id);
        assertThat(blacklist.isBlackListed(id)).isFalse();
        assertThat(blacklist.isUserBanned(id)).isFalse();
    }

    @Test
    void ignoresMissingOrNonPositiveLifetimes() {
        for (Duration ttl : new Duration[]{null, Duration.ZERO, Duration.ofSeconds(-1)}) {
            blacklist.add("token", ttl);
            blacklist.banUser("user", ttl);
        }
        assertThat(blacklist.isBlackListed("token")).isFalse();
        assertThat(blacklist.isUserBanned("user")).isFalse();
    }

    @Test
    void entriesExpireAfterTheirOwnLifetimes() {
        blacklist.add("short", Duration.ofMillis(30));
        blacklist.banUser("short", Duration.ofMillis(30));
        blacklist.add("long", Duration.ofMinutes(1));
        await().atMost(Duration.ofSeconds(2)).untilAsserted(() -> {
            assertThat(blacklist.isBlackListed("short")).isFalse();
            assertThat(blacklist.isUserBanned("short")).isFalse();
        });
        assertThat(blacklist.isBlackListed("long")).isTrue();
    }
}
