# AutoAuth

Simple access/refresh JWT authentication and role authorization for Spring Boot,
with HttpOnly cookies and automatic Swagger configuration.

AutoAuth creates and validates RSA/RS256 JWTs, protects MVC endpoints, and exposes
the authenticated user ID, roles, and custom claims. Your application owns user
accounts, credential checking, login/refresh endpoints, and refresh-session policy.

## Supported scope

- Access tokens, refresh tokens, and token-pair generation.
- Bearer headers and HttpOnly authentication cookies.
- CSRF protection whenever cookie authentication is enabled.
- Public endpoint and role annotations, plus current-user helpers.
- Automatic Swagger bearer authorization, cookie metadata, and CSRF headers.

Task tokens, account bans, token revocation stores, Redis/Caffeine, JWKS publication,
dynamic rotation, OAuth/OIDC, and account persistence are outside the library.
Rate limiting is available separately through [AutoLimit](https://github.com/AutoSprings/AutoLimit).

Tokens remain valid until expiration plus the validator's 30-second clock tolerance.
Clearing cookies removes the browser copies; it does not invalidate copied tokens.

## Build and installation

The baseline is **Java 21, Spring Boot 4.1.2 / Spring Framework 7, Spring Security 7,
and springdoc-openapi 3.1.1**. Spring Boot 3 is not the supported target for this source tree.

The current source version is `com.autoauth:autoauth:1.0.3-SNAPSHOT`.
These changes do not publish it to Maven Central.

```powershell
.\gradlew.bat clean build
.\gradlew.bat publishToMavenLocal
```

After building locally, add `mavenLocal()` to the consuming project's repositories:

```groovy
implementation 'com.autoauth:autoauth:1.0.3-SNAPSHOT'
```

AutoAuth's own build resolves dependencies from Maven Central. Tests use ephemeral
keys and require no external store. The build produces library, source, and Javadoc JARs.

## Configuration

Supply RSA keys as PEM text, a filesystem path, a `file:` URI, or a `classpath:`
resource. Private keys must be PKCS#8; public keys must be X.509 SubjectPublicKeyInfo.
Keep production private keys outside source control.

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
  # Explicitly expose Swagger/OpenAPI routes for exploration.
  swagger-public: true
  # Only needed for an approved frontend on another origin.
  allowed-origins:
    - https://app.example.com
```

Boot discovers AutoAuth automatically. `@EnableAutoAuth` is available for explicit
imports but is unnecessary in a normal Boot application. `autoauth.enabled=false`
disables AutoAuth configuration.

An RSA public key is derived from a supplied PKCS#8 CRT private key if omitted.
Verifier-only services supply `autoauth.public-key` without a private key; they
receive a validator but no generator bean. Keys must be at least 2048 bits and
a supplied pair must match. Invalid settings and missing keys fail startup.

`COOKIE_AND_BEARER` is the default. A bearer header takes precedence over the
access cookie; the refresh cookie is never used for request authentication.
Use `transport: BEARER` to ignore authentication cookies and disable AutoAuth's
CSRF checks. In cookie-enabled mode, bearer requests also require CSRF protection
for state changes, preventing a transport-based bypass.

Use `cookie-secure: false` only for local HTTP development. `SameSite=None`
requires Secure and is only necessary for cross-site deployments. CORS origins
must be explicit; an empty list permits no cross-origin browser access.
SameSite and CORS supplement CSRF protection.

## Application login and refresh

After your application verifies credentials:

```java
AutoAuthUser identity = new AutoAuthUser(
    userId, List.of("USER"), Map.of("tenantId", tenantId));
TokenPair tokens = jwtGenerator.generateTokenPair(identity);
jwtCookies.write(response, tokens);
```

Inject `JwtGenerator` and `JwtCookies` into your login controller. The helper writes
distinct access/refresh cookies with HttpOnly, Secure, SameSite, path, and lifetime
attributes. Do not also return JWTs in JSON if they should be inaccessible to JavaScript.

For bearer clients, return token strings through your application's chosen response.
`generateAccessToken` and `generateRefreshToken` are available individually.
Custom claims cannot replace `sub`, `roles`, `type`, `exp`, `iat`, `nbf`,
`jti`, `iss`, or `aud`. Keep claims within browser cookie-size limits.

Your refresh endpoint should:

1. Read the configured refresh cookie or the bearer client's supplied refresh token.
2. Call `jwtValidator.validateRefreshToken(token)`.
3. Load the current account and roles from trusted application data.
4. Apply your session/replay policy, then issue a new pair.

Refresh tokens contain identity and purpose, not copied roles/custom claims.
They cannot authenticate protected HTTP routes. Generating a pair does not revoke
the previous pair. Session tracking, atomic refresh consumption, and replay detection
remain application responsibilities.

## Browser cookies and CSRF

HttpOnly prevents JavaScript from reading the JWT cookie. It does not prevent CSRF.
Cookie mode keeps Spring CSRF checks enabled, including public login/refresh/logout routes.

Bootstrap before the first state-changing request:

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

Include the CSRF header and cookies on POST/PUT/PATCH/DELETE requests.
`XSRF-TOKEN` is a separate readable CSRF cookie; JWT cookies remain HttpOnly.
Cookies are host-only. GET endpoints must not change state. For a separate frontend
origin, use the API base URL in both requests and approve that origin explicitly.
Avoid enabling compression on the CSRF bootstrap response.

Use `jwtCookies.clear(response)` in your own CSRF-protected logout endpoint.
This clears both browser cookies without server-side token revocation.

## Public endpoints and roles

```java
@PublicEndpoint
@GetMapping("/status")
public String status() { return "ok"; }

@RequiresRole("ADMIN")
@GetMapping("/admin")
public String admin() { return "admin"; }
```

Everything else requires a valid access token. Public annotations preserve HTTP
methods and MVC mapping conditions. A public GET does not expose a protected POST;
a public controller exposes only its registered handlers. An explicitly supplied
invalid JWT returns 401 even on public endpoints.

`autoauth.public-paths` is an explicit path-pattern escape hatch applying to all
methods at matching paths. Prefer annotations for method-specific access.

Roles are case-sensitive and normalize one optional `ROLE_` prefix. `ADMIN`
and `ROLE_ADMIN` are equivalent; `admin` is different. No hierarchy is implied.
Use `@RequiresRole(value = {"ADMIN", "AUDITOR"}, requireAll = true)` to require both.
Every declaration must contain at least one role, including `requireAll = true`.
Empty/blank names, surrounding whitespace, a bare `ROLE_`, and repeated `ROLE_`
prefixes fail bean initialization with the declaration and invalid entry identified.
Superclass and interface declarations are also validated, even when overridden.
Role rules resolve in this order:

1. The nearest annotated method in the implementation's class hierarchy.
2. The most specific annotated interface method.
3. The nearest annotated type in the implementation's class hierarchy.
4. The most specific annotated interface type, for methods exposed by that interface.

An unannotated override inherits the applicable rule. Within interfaces, an annotated
child declaration overrides its annotated ancestor. Unrelated interface declarations
must agree on the role set (ignoring order, duplicates, and the optional `ROLE_` prefix)
and `requireAll`; otherwise bean initialization fails with the method and conflicting
interfaces identified. An explicit implementation method rule resolves conflicting
interface method rules. A class-level rule cannot override a method-level conflict.
Enforcement, startup validation, and Swagger role metadata use the same resolver.

Enforcement uses Spring proxies. AutoAuth rejects
role-protected beans during initialization when the configured proxy cannot enforce
their rules, normally failing application startup. Lazy beans are checked when created.
Explicit private/static role declarations are rejected. Class proxies cannot protect
final methods/classes; JDK proxies can protect final implementations through interface
methods, but protected methods must be exposed by the proxy's interfaces. Errors name
the affected bean and method. Private/static helpers under a class-level rule are not
protected. Self-invocation bypasses the proxy and remains unsupported.

```java
AuthContext.getCurrentUser();
AuthContext.getCurrentUserId();
AuthContext.getCurrentUserRoles();
AuthContext.getCustomClaim("tenantId");
```

The standard Spring Security principal is an `AutoAuthUser`. Roles are immutable.
Custom-claim maps are copied shallowly; use immutable nested claim values.

## Swagger

AutoAuth includes Swagger/OpenAPI and configures bearer JWT authorization, cookie
authentication metadata, and automatic `X-XSRF-TOKEN` headers in Swagger UI.

Enable `autoauth.swagger-public=true` for local exploration, then open
`/swagger-ui/index.html`. Paste an access token into **Authorize**, or call your
own login endpoint through Swagger to receive HttpOnly cookies. The browser sends
them automatically; Swagger cannot directly write an HttpOnly cookie. Safe page
requests bootstrap the CSRF cookie automatically.

Public annotated operations have no authentication requirement. Role metadata uses
`x-autoauth-roles` and `x-autoauth-require-all`. A custom `OpenAPI` bean owns its
top-level security schemes. Custom springdoc paths need explicit route permissions.

## Customization and migration

Application-provided validators, key providers, clocks, and cookie helpers replace
the defaults. An application-provided `SecurityFilterChain` replaces AutoAuth's
default chain; its owner must configure JWT authentication, public routes, and CSRF.

See [scope/API migration](docs/migration-simple-jwt.md) and
[rate limiting migration](docs/migration-autolimit.md).

## License

MIT.
