# Moving bundled rate limiting to AutoLimit

AutoAuth now handles authentication and authorization independently. JWTs, keys,
roles, bans, and token revocation retain their existing APIs. It no longer
contains limiter annotations, aspects, services, filters, exceptions, identity
interfaces, configuration properties, or limiter beans. No AutoLimit dependency
is introduced; authentication-only consumers do not need it.

Applications that need rate limiting must migrate explicitly:

1. Add the independent [AutoLimit](https://github.com/AutoSprings/AutoLimit)
   library. The split implementation uses `com.autolimit:autolimit:1.0.0-SNAPSHOT`;
   build from source or use an available artifact. No release is published by
   these changes.
2. Change `RateLimit`, `UserQuota`, `RateLimitAspect`, `RateLimitService`,
   `IpRateLimitFilter`, and `RateLimitExceededException` imports from
   `com.autoauth` to `com.autolimit`, preserving their package suffixes.
   Rename `AutoAuthRateLimitExceptionResolver` to
   `com.autolimit.exception.AutoLimitRateLimitExceptionResolver`.
3. Move `autoauth.pre-auth-rate-limit` to `autolimit.pre-auth-rate-limit`.
   AutoLimit defaults to 50 requests per IP per second; configure a positive
   value. `autolimit.ip-limit-enabled=false` disables the early IP filter while
   keeping annotation quotas.
4. Supply the following application-owned identity bridge for authenticated
   quotas. The `com.autolimit.identity` interfaces now live exclusively in
   AutoLimit. Neither library imports the other.

```java
import com.autoauth.util.AuthContext;
import com.autolimit.identity.CallerIdentity;
import com.autolimit.identity.CallerIdentityResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
public class LimiterIdentityConfiguration {
    @Bean
    CallerIdentityResolver callerIdentityResolver() {
        return () -> AuthContext.getCurrentUser()
                .map(user -> new CallerIdentity(user.userId(), user.roles()));
    }
}
```

The bridge runs when an annotated endpoint is invoked, after JWT authentication.
It supplies the actual user ID and roles from the validated token. An empty
result means anonymous; without an application resolver, every caller uses IP
quotas. Identity-provider failures must propagate, rather than silently using
anonymous quotas.

AutoLimit registers its IP filter once in the servlet container, at order -110,
ahead of Boot's default Spring Security filter order (-100). Do not add it to
`SecurityFilterChain`. If you customize the security servlet order, set
`autolimit.ip-filter-order` to a smaller number. Endpoint quota checks run after
authentication and remain independent of this early IP protection.

The independent [consuming example and integration tests](https://github.com/AutoSprings/AutoLimit/tree/split/independent-library/examples/autoauth-integration)
show both libraries together using source composite builds, ephemeral test keys,
real JWTs, and HTTP requests. AutoAuth's own build never includes this example.
