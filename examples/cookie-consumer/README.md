# Cookie consumer

This runnable Java 21 / Boot 4 application uses the **published artifact** through
Gradle or Maven. It has no project/composite-build dependency and no application
BOM, so it also checks the library's published dependency metadata.

It binds to `127.0.0.1`. Each startup generates a disposable RSA key in memory.
The only accounts are `alice` (USER) and `admin` (ADMIN), both with the deliberately
public demonstration password `demo-only`. These accounts and the HTTP cookie
settings are for local exploration only.

## Run from a checkout

From the repository root, stage the development artifact:

```powershell
.\gradlew.bat publishMavenJavaPublicationToStagingRepository
.\gradlew.bat -p examples/cookie-consumer '-PautoauthRepository=../../build/staging-repository' run
```

The server starts on port 8080. `autoauthVersion` and `autoauthGroup` Gradle
properties select another staged or Central version. Without `autoauthRepository`,
Gradle resolves from Central.

For Maven, use a file URI for the staging repository (replace the absolute path):

```powershell
mvn -f examples/cookie-consumer/pom.xml '-Dautoauth.repository=file:///C:/path/to/AutoAuth/build/staging-repository' package
java -jar examples/cookie-consumer/target/cookie-consumer-1.0.0.jar
```

Maven properties `autoauth.group` and `autoauth.version` select the coordinates.

## Explore the browser flow

Open `http://localhost:8080/swagger-ui/index.html`. Swagger bootstraps CSRF and
automatically sends its header on unsafe operations. Invoke POST `/login` with:

```json
{"username":"alice","password":"demo-only"}
```

The browser receives HttpOnly access and refresh cookies; JWTs are not returned
in JSON. GET `/me` authenticates with the access cookie. GET `/admin` returns 403
for alice; log in as admin to see the successful role check. POST `/refresh`
validates the refresh token, reloads the account's current roles, and issues a
new pair. POST `/logout` clears both browser cookies.

For a separate frontend, first fetch GET `/autoauth/csrf` with credentials, then
include its `headerName`/`token` and credentials on POSTs. The root README includes
the browser JavaScript. Bootstrap again after authentication changes or use the
current readable CSRF cookie before each unsafe request. Swagger **Authorize** also accepts an access token issued
by your own application; this cookie demo deliberately does not expose JWT text.
Bearer headers still require CSRF while cookie transport is enabled.

## Deliberate limits

The example has no password store, refresh-session persistence, atomic refresh
consumption, or replay detection. Production applications must own those policies.
Issuing a new pair does not invalidate copied tokens. Logout clears browser copies;
copied access/refresh tokens remain usable until expiration plus clock tolerance.
Restarting the demo changes its signing key and loses its ephemeral state.

Run the complete staged-publication checks with Python 3.11+:

```powershell
python scripts/verify-publication.py
```

This builds the independent Gradle and Maven consumers and verifies real HTTP
CSRF, login, cookies, access, refresh, roles, logout, and Swagger flows. If Maven
is absent, the verifier downloads a pinned Apache distribution into ignored
`build/tools` output and checks its SHA-512. Logs are in `build/reports/publication`.
