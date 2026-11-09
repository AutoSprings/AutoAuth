package com.autoauth.jwt;

import com.autoauth.config.AutoAuthProperties;
import com.autoauth.model.TokenPair;
import com.autoauth.model.AutoAuthUser;
import com.autoauth.support.TestKeys;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.http.ResponseCookie;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import static org.assertj.core.api.Assertions.*;

class JwtCookiesTest {
    @Test void writesDistinctHttpOnlySecureCookiesAndClearsWithMatchingAttributes() {
        var cookies = new JwtCookies(new AutoAuthProperties());
        var response = new MockHttpServletResponse();
        cookies.write(response, new TokenPair("access", "refresh"));
        assertThat(response.getHeaders("Set-Cookie")).hasSize(2).allSatisfy(value ->
                assertThat(value).contains("HttpOnly", "Secure", "SameSite=Lax", "Path=/"));
        assertThat(response.getHeaders("Set-Cookie").get(0)).contains("AUTOAUTH=access", "Max-Age=900");
        assertThat(response.getHeaders("Set-Cookie").get(1)).contains("AUTOAUTH_REFRESH=refresh", "Max-Age=604800");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("no-store");
        var cleared = new MockHttpServletResponse();
        cookies.clear(cleared);
        assertThat(cleared.getHeaders("Set-Cookie")).hasSize(2).allSatisfy(value -> assertThat(value).contains("Max-Age=0", "HttpOnly", "Secure"));
    }
    @Test void sameSiteNoneRequiresSecureAndBearerModeRejectsCookieCreation() {
        var properties = new AutoAuthProperties();
        properties.setCookieSameSite("None");
        properties.setCookieSecure(false);
        assertThatThrownBy(properties::validate).isInstanceOf(IllegalArgumentException.class);
        properties.setTransport(AutoAuthProperties.Transport.BEARER);
        assertThatThrownBy(() -> new JwtCookies(properties).access("access")).isInstanceOf(IllegalStateException.class);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void sizeBoundariesIncludeCustomNamesAndAllSerializedAttributes(boolean refresh) {
        for (boolean secure : new boolean[]{false, true}) {
            var properties = new AutoAuthProperties();
            properties.setCookieName("CUSTOM_ACCESS_" + "a".repeat(40));
            properties.setRefreshCookieName("CUSTOM_REFRESH_" + "r".repeat(60));
            properties.setCookieSecure(secure);
            properties.setCookieSameSite(secure ? "None" : "Strict");
            var cookies = new JwtCookies(properties);
            int overhead = size(cookie(cookies, refresh, "a")) - 1;
            int tokenLength = properties.getMaxCookieSize() - overhead;
            assertThat(size(cookie(cookies, refresh, "a".repeat(tokenLength - 1))))
                    .isEqualTo(properties.getMaxCookieSize() - 1);
            assertThat(size(cookie(cookies, refresh, "a".repeat(tokenLength))))
                    .isEqualTo(properties.getMaxCookieSize());
            assertThatThrownBy(() -> cookie(cookies, refresh, "a".repeat(tokenLength + 1)))
                    .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("autoauth.max-cookie-size=3800")
                    .hasMessageContaining(refresh ? properties.getRefreshCookieName() : properties.getCookieName());
        }
    }

    @Test
    void rejectsOversizedAccessOrRefreshWithoutChangingTheResponse() {
        var cookies = new JwtCookies(new AutoAuthProperties());
        String oversized = "a".repeat(3800);
        assertUnchanged(response -> cookies.write(response, new TokenPair(oversized, "refresh")));
        assertUnchanged(response -> cookies.write(response, new TokenPair("access", oversized)));
        assertUnchanged(response -> cookies.write(response, null));
    }

    @Test
    void rejectsInvalidValuesWithoutDisclosingTokensOrWritingPartialPairs() {
        var cookies = new JwtCookies(new AutoAuthProperties());
        for (String invalid : new String[]{null, "", " ", "a b", "secret; Path=/", "secret,other", "secret\\other",
                "\"secret\"", "secret\r\nSet-Cookie: injected=value", "secret\t", "s\u00e9cret", "a=b", "a+b", "a/b"}) {
            assertThatThrownBy(() -> cookies.access(invalid)).isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Cookie token must be nonempty and contain only JWT characters");
            assertThatThrownBy(() -> cookies.refresh(invalid)).isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("Cookie token must be nonempty and contain only JWT characters");
            assertUnchanged(response -> cookies.write(response, new TokenPair(invalid, "refresh")));
            assertUnchanged(response -> cookies.write(response, new TokenPair("access", invalid)));
        }
    }

    @Test
    void acceptsJwtAlphabetAndConfigurableLargerCookieBudgets() {
        var properties = new AutoAuthProperties();
        var cookies = new JwtCookies(properties);
        assertThat(cookies.access("AZaz09._-").getValue()).isEqualTo("AZaz09._-");
        String token = "a".repeat(3900);
        assertUnchanged(response -> cookies.write(response, new TokenPair(token, token)));
        properties.setMaxCookieSize(4096);
        var response = new MockHttpServletResponse();
        cookies.write(response, new TokenPair(token, token));
        assertThat(response.getHeaders("Set-Cookie")).hasSize(2).allSatisfy(header ->
                assertThat(header.getBytes(StandardCharsets.UTF_8).length).isLessThanOrEqualTo(4096));
    }

    @Test
    void largeCustomClaimsRemainValidJwtInputsButCannotBeWrittenAsCookies() {
        var properties = TestKeys.properties();
        var keys = new JwtKeyProvider(properties);
        var generator = new JwtGenerator(keys, properties);
        var validator = new JwtValidator(keys, properties);
        var user = new AutoAuthUser("alice", List.of("USER"), Map.of("large", "a".repeat(3000)));
        TokenPair pair = generator.generateTokenPair(user);
        assertThat(pair.accessToken().length()).isGreaterThan(properties.getMaxCookieSize())
                .isLessThan(properties.getMaxTokenLength());
        assertThat(validator.validateAccessToken(pair.accessToken())).isEqualTo(user);
        assertThat(validator.validateRefreshToken(pair.refreshToken()).userId()).isEqualTo("alice");
        var cookies = new JwtCookies(properties);
        assertUnchanged(response -> cookies.write(response, pair));
        var response = new MockHttpServletResponse();
        cookies.clear(response);
        assertThat(response.getHeaders("Set-Cookie")).hasSize(2).allSatisfy(header -> assertThat(header).contains("Max-Age=0"));
    }

    @Test
    void rejectsInvalidBudgetsAndOversizedDeletionCookiesWithoutPartialClearing() {
        var properties = new AutoAuthProperties();
        var cookies = new JwtCookies(properties);
        for (int budget : new int[]{0, -1}) {
            properties.setMaxCookieSize(budget);
            assertThatThrownBy(properties::validate).isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("autoauth.max-cookie-size must be positive");
            assertUnchanged(response -> cookies.write(response, new TokenPair("access", "refresh")));
            assertUnchanged(cookies::clear);
        }
        properties.setMaxCookieSize(3800);
        properties.setRefreshCookieName("r".repeat(3800));
        assertUnchanged(cookies::clear);
    }

    private ResponseCookie cookie(JwtCookies cookies, boolean refresh, String token) {
        return refresh ? cookies.refresh(token) : cookies.access(token);
    }

    private int size(ResponseCookie cookie) {
        return cookie.toString().getBytes(StandardCharsets.UTF_8).length;
    }

    private void assertUnchanged(Consumer<MockHttpServletResponse> operation) {
        var response = new MockHttpServletResponse();
        response.addHeader("Set-Cookie", "unrelated=keep");
        response.setHeader("Cache-Control", "private");
        assertThatThrownBy(() -> operation.accept(response)).isInstanceOf(IllegalArgumentException.class);
        assertThat(response.getHeaders("Set-Cookie")).containsExactly("unrelated=keep");
        assertThat(response.getHeader("Cache-Control")).isEqualTo("private");
    }
}
