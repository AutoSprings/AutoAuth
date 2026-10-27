package com.autoauth.blacklist;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RedisTokenBlackListTest {
    @Mock private StringRedisTemplate redis;
    @Mock private ValueOperations<String, String> values;
    private RedisTokenBlackList blacklist;

    @BeforeEach
    void setUp() {
        blacklist = new RedisTokenBlackList(redis);
    }

    @Test
    void writesRevocationsAndBansWithSeparatePrefixesAndTtl() {
        when(redis.opsForValue()).thenReturn(values);
        Duration ttl = Duration.ofMinutes(5);
        blacklist.add("token", ttl);
        blacklist.banUser("user", ttl);
        verify(values).set("blacklist:token", "revoked", ttl);
        verify(values).set("banned:user", "true", ttl);
    }

    @Test
    void looksUpRevocationsAndBans() {
        when(redis.hasKey("blacklist:token")).thenReturn(true);
        when(redis.hasKey("banned:user")).thenReturn(true);
        assertThat(blacklist.isBlackListed("token")).isTrue();
        assertThat(blacklist.isUserBanned("user")).isTrue();
        assertThat(blacklist.isBlackListed("missing")).isFalse();
        assertThat(blacklist.isUserBanned("missing")).isFalse();
    }

    @Test
    void unbanDeletesOnlyTheUserBan() {
        blacklist.unbanUser("user");
        verify(redis).delete("banned:user");
        verifyNoMoreInteractions(redis);
    }
}
