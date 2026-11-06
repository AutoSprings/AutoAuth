package com.autoauth.jwt;

/** Supported token purposes. Only ACCESS tokens authenticate HTTP requests. */
public enum TokenType {
    ACCESS("access"), REFRESH("refresh");
    private final String value;
    TokenType(String value) { this.value = value; }
    public String getValue() { return value; }
    public static TokenType fromString(String value) {
        for (TokenType type : values()) if (type.value.equalsIgnoreCase(value)) return type;
        throw new IllegalArgumentException("Unsupported token type");
    }
}
