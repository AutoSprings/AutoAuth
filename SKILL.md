---
name: autoauth
description: Integrate and configure the AutoAuth JWT library in Spring Boot servlet applications, including access and refresh tokens, HttpOnly cookies, CSRF, endpoint authorization, and current-user access. Use when a task names AutoAuth or io.github.autosprings:autoauth.
---

# Use AutoAuth

AutoAuth supplies RSA/RS256 JWT generation and validation, MVC authentication,
role authorization, cookie helpers, and Swagger integration. Target Java 21 /
Spring Boot 4 servlet applications; WebFlux and Boot 3 are outside this integration
path. The library baseline is Boot 4.1.2, Spring Framework/Security 7, and
springdoc-openapi 3.1.1. Preserve the consuming application's compatible platform
and inspect dependency resolution when it overrides versions.

The application owns accounts, password verification, login/refresh/logout
handlers, and refresh-session policy. AutoAuth does not supply account persistence,
revocation, bans, refresh replay detection, OAuth/OIDC, JWKS publication, dynamic
key rotation, or rate limiting. AutoLimit is a separate dependency.

## Install the published library

Use `io.github.autosprings:autoauth:1.0.0` from Maven Central.

Gradle (Groovy):

```groovy
repositories { mavenCentral() }
dependencies { implementation 'io.github.autosprings:autoauth:1.0.0' }
```

Maven (Central is available by default):

```xml
<dependency>
    <groupId>io.github.autosprings</groupId>
    <artifactId>autoauth</artifactId>
    <version>1.0.0</version>
</dependency>
```

No checkout, local publication, or component scan of `com.autoauth` is needed.
Boot auto-configures the library; `com.autoauth.annotation.EnableAutoAuth` is
optional for explicit imports. `autoauth.enabled=false` disables configuration.

## Configure keys and transport

```yaml
autoauth:
  private-key: file:/run/secrets/jwt-private.pem
  issuer: my-service
  audience: my-api
  expiration-minutes: 15
  refresh-expiration-minutes: 10080
  transport: COOKIE_AND_BEARER
  cookie-name: AUTOAUTH
  refresh-cookie-name: AUTOAUTH_REFRESH
  cookie-secure: true
  cookie-same-site: Lax
  max-cookie-size: 3800
  max-token-length: 16384
  swagger-public: false
  allowed-origins: []
  public-paths: []
```

These are the defaults except the key, issuer, and audience. Choose issuer and
audience consistently across issuers and verifiers. Lifetimes must be positive;
`max-token-length` must be at least 256 and `max-cookie-size` must be positive.

- Keys accept PEM text, filesystem paths, `file:` URIs, or `classpath:` resources.
  Use RSA keys of at least 2048 bits, PKCS#8 private keys (`BEGIN PRIVATE KEY`),
  and X.509 SubjectPublicKeyInfo public keys (`BEGIN PUBLIC KEY`). Keep production
  private keys outside source control and stable across restarts/issuing replicas.
- A public key is derived from a supplied CRT private key when omitted. A supplied
  pair must match. A verifier-only service supplies `autoauth.public-key` without
  a private key: it gets a `JwtValidator`, but no `JwtGenerator` bean.
- Default `COOKIE_AND_BEARER` authenticates from a bearer header first, then the
  access cookie. A supplied invalid bearer credential cannot fall back to cookies.
  The refresh cookie never authenticates protected routes.
- Choose `transport: BEARER` for bearer-only applications. It ignores authentication
  cookies and disables AutoAuth's CSRF checks. In cookie-enabled mode, unsafe
  bearer requests still require CSRF protection.
- Use `cookie-secure: false` only for local HTTP. `SameSite=None` requires Secure;
  use it only when cross-site cookies are needed. Cookies are host-only with path
  `/`. Cookie names must be distinct, use letters/digits/underscore/hyphen, and
  must not be `XSRF-TOKEN`.
- Approve exact frontend origins with `allowed-origins`; wildcards are rejected.
  An empty list permits no cross-origin browser access. CORS and SameSite do not
  replace CSRF protection.

## Issue and refresh credentials

Inject `JwtGenerator`, `JwtValidator`, and `JwtCookies` where needed. Imports:

```java
import com.autoauth.jwt.JwtGenerator;
import com.autoauth.jwt.JwtValidator;
import com.autoauth.jwt.JwtCookies;
import com.autoauth.model.AutoAuthUser;
import com.autoauth.model.TokenPair;
import com.autoauth.exception.JwtValidationException;
import java.util.List;
import java.util.Map;
```

After the application's credential check succeeds, build the identity from trusted
account data, never from client-supplied user IDs, roles, or claims:

```java
AutoAuthUser identity = new AutoAuthUser(
    userId, List.of("USER"), Map.of("tenantId", tenantId));
TokenPair tokens = jwtGenerator.generateTokenPair(identity);
jwtCookies.write(response, tokens); // jakarta.servlet.http.HttpServletResponse
```

`AutoAuthUser` is a record with `userId()`, `roles()`, and `customClaims()`.
The ID is a nonblank `String`; roles are `List<String>` and claims are
`Map<String, Object>`. Roles are immutable; claim copying is shallow, so keep
nested values immutable. Do not put secrets in JWT claims: signing does not
encrypt them. Reserved claims are `sub`, `roles`, `type`, `exp`, `iat`, `nbf`,
`jti`, `iss`, and `aud`; custom access claims cannot replace them.

Public API:

| Call | Result |
| --- | --- |
| `jwtGenerator.generateTokenPair(identity)` | `TokenPair` |
| `jwtGenerator.generateAccessToken(identity)` | access JWT `String` |
| `jwtGenerator.generateRefreshToken(identity)` | refresh JWT `String` |
| `tokens.accessToken()` / `tokens.refreshToken()` | individual JWT strings |
| `jwtValidator.validateAccessToken(token)` | validated `AutoAuthUser` |
| `jwtValidator.validateRefreshToken(token)` | validated subject as `AutoAuthUser` |
| `jwtCookies.write(response, tokens)` | writes both HttpOnly cookies |
| `jwtCookies.clear(response)` | writes both deletion cookies |

For bearer clients, return the strings through the application's response format;
clients send `Authorization: Bearer <access-token>`. Avoid returning JWTs in JSON
when the chosen browser design keeps them inaccessible to JavaScript.

Implement refresh as an anonymous-permitted handler (`@PublicEndpoint`), since
the access token may have expired. Read the configured refresh cookie (reject
duplicates) or the bearer client's explicit refresh input, then:

1. Call `validateRefreshToken(token)` and handle `JwtValidationException` as an
   authentication failure without exposing the raw token.
2. Reload the account, enabled status, current roles, and claims from trusted data.
   Refresh tokens contain identity and purpose, not copied roles/custom claims.
3. Apply the application's refresh-session policy, including atomic consumption
   and replay detection if required, then generate and deliver a new pair.

Generating a pair does not revoke older tokens. Logout clears browser cookies;
copied tokens remain valid until expiration plus the 30-second validation tolerance.
Use an application-owned store/policy when immediate invalidation is required.

Keep cookie claims small. The 3800-byte default counts each complete serialized
`Set-Cookie` value, including name and attributes; the 16384-character token limit
is separate. Oversized/invalid cookie values throw `IllegalArgumentException`.
`write` validates both cookies before writing either, and does not validate JWT
signatures or purposes itself. Raising the budget does not guarantee browser storage.

## Wire browser CSRF

Cookie mode protects all unsafe requests, including public login/refresh/logout.
Bootstrap before the first mutation and send cookies plus the returned header:

```javascript
const csrf = await fetch("/autoauth/csrf", { credentials: "include" })
  .then(response => response.json());

await fetch("/api/login", {
  method: "POST",
  credentials: "include",
  headers: {
    "Content-Type": "application/json",
    [csrf.headerName]: csrf.token
  },
  body: JSON.stringify({ username, password })
});
```

Send the CSRF header on POST/PUT/PATCH/DELETE. Bootstrap again after authentication
changes or read the current `XSRF-TOKEN` cookie; do not reuse a stale token across
login/logout. The readable CSRF cookie is separate from the HttpOnly JWT cookies.
Use the API base URL for both calls when the frontend has another origin. Avoid
compressing the bootstrap response. GET handlers must not change state.

The default chain allows an otherwise verified but expired access cookie to be
ignored on anonymous-permitted routes, including public refresh and CSRF bootstrap.
It continues anonymously and still requires CSRF for unsafe requests. Protected
routes reject expired access cookies. Malformed, duplicate, wrong-signature, or
wrong-purpose access cookies still produce 401 on public routes; invalid/expired
bearer headers also produce 401 there. `ExpiredAccessTokenException` extends
`JwtValidationException` and identifies only the verified access-expiry case;
validation never returns an expired identity.

## Authorize endpoints and read the caller

```java
import com.autoauth.annotation.PublicEndpoint;
import com.autoauth.annotation.RequiresRole;
import com.autoauth.util.AuthContext;
import org.springframework.web.bind.annotation.GetMapping;

// Inside a Spring-managed @RestController:
@PublicEndpoint
@GetMapping("/status")
public String status() { return "ok"; }

@RequiresRole("ADMIN")
@GetMapping("/admin")
public String admin() { return "admin"; }
```

All other handlers require a valid access token under the default chain.
`@PublicEndpoint` preserves registered MVC methods and mapping conditions; a
public GET does not expose POST. `public-paths` instead permits every method at
matching paths; configure patterns relative to the application context.

Roles are case-sensitive with one optional `ROLE_` prefix: `ADMIN` equals
`ROLE_ADMIN`, but differs from `admin`. No hierarchy is implied. Multiple roles
default to any-of; `@RequiresRole(value = {"ADMIN", "AUDITOR"}, requireAll = true)`
requires both. Empty/invalid declarations fail bean initialization. Method rules
override type rules; unannotated overrides inherit applicable rules. Conflicting
unrelated interface rules require an explicit implementation rule.

Role enforcement uses Spring proxies. Use public, non-final methods on
Spring-managed beans and call through the proxy; self-invocation bypasses checks.
Private/static role declarations and unenforceable final/class-proxy combinations
are rejected. With JDK proxies, protected methods must be exposed by interfaces.

`AuthContext` exposes these exact return types:

| Method | Return type |
| --- | --- |
| `getCurrentUser()` | `Optional<AutoAuthUser>` |
| `getCurrentUserId()` | `Optional<String>` |
| `getCurrentUserRoles()` | `Optional<List<String>>` |
| `getCustomClaim("tenantId")` | `Optional<Object>` |

The Spring Security principal is `AutoAuthUser`. Handle anonymous optionals
explicitly. Application-created background tasks need explicit security-context
propagation. For AutoLimit integration, adapt `getCurrentUser()` into its
`CallerIdentity(user.userId(), user.roles())` in an application-owned resolver.

## Swagger and custom security

Swagger/OpenAPI is included. `autoauth.swagger-public=true` exposes registered
springdoc GET handlers and dedicated UI resources; the default is false. Open
`/swagger-ui/index.html` and authorize with an access token or use the application's
login endpoint to receive cookies. Swagger UI reads the current CSRF cookie for
unsafe requests. Custom documentation paths and grouped documents are supported.

Prefer the default security chain for ordinary integrations. Declaring any
`SecurityFilterChain` bean replaces AutoAuth's entire default chain: the application
then owns JWT filter installation, stateless sessions, anonymous matchers, CORS,
CSRF, denial handlers, dispatcher coverage, and a final catch-all chain.
`@PublicEndpoint` alone does not configure permissions in a custom chain.
Role proxies continue to enforce their rules with the authenticated identity.

For custom chains or servlet dispatch changes, read
[docs/endpoint-security.md](docs/endpoint-security.md). Expiry-only cookie recovery
requires the same anonymous-request matcher in `permitAll` and the three-argument
`JwtAuthenticationFilter(validator, properties, publicRequests)`; the two-argument
constructor is strict. Preserve REQUEST/FORWARD/ERROR/ASYNC security dispatches.
Errors and forwarded targets receive no implicit public exemption.

## Verify the consuming application

Use its existing HTTP integration tests through Spring. Exercise anonymous access,
valid/invalid/expired access tokens, 401 versus role-denied 403, and public-method
boundaries. For cookie mode, exercise CSRF bootstrap, missing/valid CSRF headers,
login, refresh after access expiry, duplicate refresh input, and logout cookie
deletion. Ensure refresh uses current account roles and the intended session policy.
Verifier-only services should start with a public key and reject refresh tokens
as access credentials. Keep test keys disposable and separate from production keys.

For a runnable Gradle/Maven consumer, see
[examples/cookie-consumer/README.md](examples/cookie-consumer/README.md). See
[README.md](README.md) for detailed role inheritance and customization, and
[docs/migration-simple-jwt.md](docs/migration-simple-jwt.md) when replacing older APIs.
