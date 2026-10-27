# AutoAuth

Zero‑Boilerplate JWT Security for Spring Boot

AutoAuth is a lightweight, annotation‑driven authentication and authorization framework for Spring Boot.
It eliminates the boilerplate typically required for JWT security, key management, revocation, rate limiting, and endpoint protection.
Instead of wiring filters, keys, and validators manually, AutoAuth provides secure defaults and configures everything automatically.
Focus on your endpoints — not your security plumbing.

## ✨ Why AutoAuth?

### ✔️ Ultra‑Fast Setup
Install the dependency → add @EnableAutoAuth → provide keys → done.
No custom Spring Security DSL required.

### ✔️ Annotation‑First Developer Experience
Define your security rules directly in your controller code:

```java
@PublicEndpoint
@GetMapping("/open")

@RequiresRole("ADMIN")
@GetMapping("/admin")

@RateLimit({
    @UserQuota(role = "USER", maxRequests = 3),
    @UserQuota(role = "PREMIUM", maxRequests = 10)
})
@GetMapping("/data")
```

AutoAuth turns simple annotations into a full security configuration.

### ✔️ Built for Microservices
AutoAuth automatically exposes an RFC‑compliant JWKS endpoint:
```
/.well-known/jwks.json
```

Other services (Go, Node, Python, Rust, etc.) can verify tokens instantly.

### ✔️ Secure by Default
AutoAuth handles the difficult parts automatically:

- RS256 signing + validation
- kid‑based key rotation
- RFC‑compliant JWKS generation
- Issuer & audience enforcement
- Clock‑skew tolerance
- Access + Refresh token support
- jti‑based token revocation
- User banning
- Method‑level AOP authorization
- Role normalization (ROLE_*)
- Auto‑generated SecurityFilterChain

### ✔️ AI‑Optimized
Annotation‑driven design enables AI agents to scaffold entire auth systems using
70–90% fewer tokens, reducing cost and improving quality.

## 🔐 Core Features

### 1. JWT Generation & Validation (RS256)

- Access & Refresh tokens
- PKCS#8 private key + X.509 public key loading
- Custom claims
- Deterministic kid
- Issuer & audience validation
- Optional EC / EdDSA support

### 2. RFC‑Compliant JWKS Endpoint
Automatically exposed at:
```
/.well-known/jwks.json
```

Includes:
- Multi‑key rotation
- Correct base64url encoding
- Deterministic thumbprint‑based kid
- Cache‑control headers
- Compatible with all major languages

### 3. Automatic SecurityFilterChain
AutoAuth generates a complete, production‑ready security configuration:

- @PublicEndpoint methods → permitAll
- All others → JWT required
- Stateless sessions
- CSRF disabled
- Configurable CORS defaults

No custom DSL — everything is inferred automatically.

### 4. Authorization Annotations

**@PublicEndpoint**
Marks a method or controller as publicly accessible.

**@RequiresRole("ADMIN")**
Enforces role‑based access control.

**@RateLimit + @UserQuota**
Tier‑based rate limiting using Caffeine or Redis.
Supports:
- Token bucket / leaky bucket
- Per‑user + per‑endpoint keys
- SaaS tiering (FREE → PREMIUM → ENTERPRISE)

### 5. User Banning

- `banned:{userId}` cache key
- Tokens instantly denied
- Refresh tokens invalidated
- Distributed cache support (Redis recommended)

### 6. Token Revocation (Blacklist)

- Revokes via jti
- TTL matches token expiration
- Supports Redis or in‑memory storage

### 7. KeyLoader Enhancements

- PEM parsing
- PKCS#1 → PKCS#8 auto‑detection
- Certificate (X.509) support
- Internal caching for performance

### 8. Full Test Suite
Covers:
- Token lifecycle
- JWKS correctness
- Revocation logic
- Banning logic
- AOP role enforcement
- Filter behavior

### 9. Example Application Included
Demonstrates:
- Login
- Access + Refresh token issuance
- Refresh flow
- Admin + public routes
- Revocation
- JWKS verification

## 🧭 Use Cases

- Microservices authentication
- Internal service‑to‑service authorization
- Role‑based access control
- Tier‑based rate limiting (SaaS)
- User banning + incident response
- AI‑assisted development with minimal boilerplate

## Running tests

The JUnit 5 suite lives in `src/test/java`. It covers JWT generation and validation,
key loading and rotation, JWKS, token revocation and user bans, role checks,
rate limits, request filters, error responses, and Spring configuration.
Tests generate their own keys and mock Redis; no external services are required.
Use Java 21 and the included Gradle wrapper:

```powershell
.\gradlew.bat test         # Run the test suite
.\gradlew.bat build        # Build the library and run tests
.\gradlew.bat clean build  # Rebuild and run tests from scratch
```

On macOS/Linux, use `./gradlew` instead. Gradle's `build` and `check` tasks already
depend on `test`, so a failing test fails the build. The HTML test report is at
`build/reports/tests/test/index.html`.

## Installation

```xml
<dependency>
    <groupId>com.autoauth</groupId>
    <artifactId>autoauth</artifactId>
    <version>1.0.0</version>
</dependency>
```

## 💡 Why AutoAuth Instead of Spring Authorization Server?
Choose AutoAuth when you want:

- JWT security without OAuth/OIDC complexity
- Simple annotations instead of large security DSLs
- Instant cross‑language token verification (JWKS)
- Built‑in revocation, rate limiting, and banning
- Lightweight microservice‑friendly auth
- AI‑friendly, low‑boilerplate design

## 📚 Documentation

For more information, see the [documentation](./docs).

## 🚀 Summary
AutoAuth provides production-grade JWT authentication and authorization with almost no configuration.
It delivers secure defaults, clean annotations, microservice compatibility, and a development experience that AI can build on with dramatically fewer tokens.

## 📄 License

MIT
