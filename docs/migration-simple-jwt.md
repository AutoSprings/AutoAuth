# Migration to the focused JWT scope

This is a breaking API cleanup of the unreleased source tree. Existing consumers
must update before using the new artifact.

## Retained

- Access/refresh JWTs, TokenPair, user IDs, roles, and custom claims.
- PublicEndpoint, RequiresRole, AuthContext, JwtGenerator, JwtValidator.
- Automatic Swagger configuration and bearer authorization.
- Cookie authentication, now with CSRF protection and explicit cookie helpers.

## Removed

- Task tokens: generateTaskToken, validateTaskToken, TokenType.TASK.
- TokenBlackList, CafeTokenBlackList, RedisTokenBlackList, TokenRevokedException,
  JwtValidator.revokeToken, and built-in user bans.
- Redis and Caffeine dependencies.
- JwksController and automatic JWKS publication.
- Verification-key registration/rotation APIs and mixed signing algorithms.
- Unused jwtSecret configuration and hand-written PKCS#1 conversion.

Use application-owned account/session controls where needed. Tokens remain valid
until expiration plus the 30-second accepted skew. A copied refresh token remains
usable until expiration unless the application enforces its own replay/session policy.

## Spring Boot 4 baseline

This tree targets Java 21 and Spring Boot 4.1.2 (Spring Framework/Security 7),
with springdoc-openapi 3.1.1. Consumers must upgrade from Boot 3 before adopting it.
The MVC and AspectJ dependencies use Boot 4's spring-boot-starter-webmvc and
spring-boot-starter-aspectj modules. Tests use the webmvc/security test starters;
AutoConfigureMockMvc now comes from org.springframework.boot.webmvc.test.autoconfigure.

Boot's HTTP JSON stack uses Jackson 3. JJWT's jjwt-jackson adapter currently
retains its own Jackson 2 runtime dependency; no application-wide Jackson 2
HTTP converter is installed by AutoAuth.

## Constructor and configuration changes

- JwtValidator now takes (JwtKeyProvider, AutoAuthProperties[, Clock]).
- JwtGenerator supports an injected Clock.
- JwtAuthenticationFilter takes (JwtValidator, AutoAuthProperties).
- RoleAspect is now a Spring AOP advisor; custom proxy factories must addAdvisor,
  rather than addAspect.
- EndpointScanner is a request matcher over actual MVC handlers, not a path inventory.
- Supply at least an RSA public verification key; missing keys now fail startup.
- PKCS#8 RSA private keys and X.509 SubjectPublicKeyInfo public keys are supported.
- transport defaults to COOKIE_AND_BEARER; BEARER disables cookie authentication.
- cookie-name defaults to AUTOAUTH; refresh-cookie-name defaults to AUTOAUTH_REFRESH.
- cookie-secure defaults to true; cookie-same-site defaults to Lax.
- swagger-public defaults to false; enable it deliberately for public documentation.
- Blank issuer/audience, invalid lifetimes, wildcard CORS origins, and conflicting
  cookie names are rejected.
- Roles are case-sensitive and normalize one optional ROLE_ prefix; no hierarchy exists.

## Browser clients

Obtain a CSRF token using GET /autoauth/csrf before login. Send its token in
X-XSRF-TOKEN and include cookies on state-changing requests. Login/refresh/logout
being public does not exempt them from CSRF. Swagger handles this header automatically.
In cookie-enabled mode the same CSRF requirement applies to bearer requests.

Use JwtCookies.write(response, tokenPair) after credential/account verification.
Use JwtCookies.clear(response) to clear both cookies on browser logout.
Never return JWTs to JavaScript when the goal is HttpOnly-only token storage.

## Release follow-ups

The scope change does not publish or tag a release. Before Maven Central publication:
finalize the license, verified namespace and coordinates, POM metadata, signing,
upload workflow, CI, dependency review, and a clean consumer artifact-resolution check.
