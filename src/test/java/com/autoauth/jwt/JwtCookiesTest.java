package com.autoauth.jwt;

import com.autoauth.config.AutoAuthProperties;
import com.autoauth.model.TokenPair;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletResponse;
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
}
