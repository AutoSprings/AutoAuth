package com.autoauth.jwt;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Locale;

import static org.assertj.core.api.Assertions.*;

class TokenTypeTest {
    @ParameterizedTest
    @EnumSource(TokenType.class)
    void parsesSerializedValuesIgnoringCase(TokenType type) {
        assertThat(TokenType.fromString(type.getValue())).isEqualTo(type);
        assertThat(TokenType.fromString(type.getValue().toUpperCase(Locale.ROOT))).isEqualTo(type);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"unknown", " "})
    void rejectsUnsupportedTypes(String value) {
        assertThatThrownBy(() -> TokenType.fromString(value)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void serializedValuesMatchJwtClaims() {
        assertThat(TokenType.ACCESS.getValue()).isEqualTo("access");
        assertThat(TokenType.REFRESH.getValue()).isEqualTo("refresh");
        assertThat(TokenType.TASK.getValue()).isEqualTo("task");
    }
}
