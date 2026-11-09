# Endpoint security and servlet dispatch

The default chain requires an access token unless the target is a registered
`@PublicEndpoint` MVC handler, an explicit `autoauth.public-paths` match, the GET
CSRF bootstrap handler, or deliberately exposed springdoc documentation.
Cookie-enabled transport also requires CSRF protection for unsafe requests,
including public handlers.

## Paths and methods

Match paths relative to the application context. For example:

```yaml
server:
  servlet:
    context-path: /app
autoauth:
  public-paths:
    - /status
```

This permits `/app/status` for every HTTP method. It does not permit unrelated
paths. Prefer `@PublicEndpoint` on individual handlers when only specific methods
or MVC mapping conditions should be public. Inherited mappings and mapping aliases
use the same registered-handler lookup. MVC's implicit HEAD mapping for a public
GET is public; an automatic OPTIONS response is not an annotated public handler.
CORS preflights use the configured CORS policy instead of blanket OPTIONS permits.

## Forwards, errors, and asynchronous work

Each security-filter dispatch authorizes the current target path and mapping
conditions. A public handler or servlet cannot grant anonymous access to a
protected target by forwarding or asynchronously dispatching to it. Target role
annotations still apply. The matcher refreshes cached request paths when the
same servlet request is reused for another target.

JWT validation runs on async and error dispatches so valid credentials can rebuild
the thread's authentication. Spring MVC Callable continuations also retain the
Spring Security context. Application-created background tasks outside servlet/MVC
dispatch need their own explicit context propagation.

Error handlers receive no implicit anonymous exemption. A protected error handler
returns 401 for anonymous requests and 403 for an authenticated user lacking its
required role. Mark only the intended error handler public if anonymous errors
should be visible, and return information appropriate for anonymous callers.

The servlet container must invoke `springSecurityFilterChain` for REQUEST,
FORWARD, ERROR, and ASYNC dispatches. Preserve these mappings when customizing
Boot's `spring.security.filter.dispatcher-types` or registering the filter in
another servlet container. Omitting a dispatcher type prevents the security
chain from checking that dispatch. The real-container regression suite verifies
the supported Boot baseline's registration, not just simulated MockMvc dispatches.

## Documentation exposure

`autoauth.swagger-public=true` permits GET requests resolved to springdoc's own
MVC handlers and dedicated UI resource handlers. This follows configured API/UI
paths, YAML and grouped specifications, and Swagger configuration/resources.
It does not whitelist all application handlers under a documentation prefix or
keep old default URLs public after the documentation moves. Leave this setting
false to require authentication for documentation.

## Application-owned security chains

Declaring any `SecurityFilterChain` bean replaces AutoAuth's entire default chain.
AutoAuth does not append a fallback chain or merge its route permissions into
application chains. The application owns:

- Chain order and `securityMatcher` boundaries. Only the first matching chain runs;
  provide a final catch-all chain so unmatched requests remain protected.
- JWT filter installation in each relevant chain, stateless session policy,
  authentication/denial handlers, CORS, and cookie-mode CSRF protection.
- Public permissions, CSRF bootstrap access, and deliberate Swagger exposure.
  `@PublicEndpoint` alone does not configure a custom chain's authorization rules.
- Security filter dispatcher registration, including forwards, errors, and async.

Use `EndpointScanner` when a custom chain should honor public MVC annotations.
For expiry-only access-cookie recovery, pass exactly the same anonymous-request
matcher to the three-argument `JwtAuthenticationFilter` constructor and to
`permitAll`; retain CSRF protection in cookie-enabled mode. The two-argument
constructor continues to reject expired access cookies on all routes.

Role annotations remain enforced by AutoAuth's method proxies even with custom
chains. A chain must authenticate the request to provide those proxies with the
correct identity and roles. The proxy limitations described in the README still
apply.
