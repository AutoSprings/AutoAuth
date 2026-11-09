# Dependency maintenance

The verification baseline is Java 21, Boot 4.1.2, springdoc 3.1.1, and JJWT 0.12.5.
`gradle.lockfile` records the exact production, test, and annotation-processor
modules. Strict locking rejects missing/stale lock state. Locks apply to this
repository; consuming applications must also scan their own resolved dependencies.

## Automation

- Dependabot checks Gradle and GitHub Actions weekly. Boot's repeated BOM
  declarations and JJWT's three modules are grouped into coherent update PRs.
- The `Dependencies` workflow resolves and scans the complete lockfile with
  OSV-Scanner on PRs, pushes to main, weekly, and on manual dispatch. This includes
  transitive and test dependencies. Findings and scanner failures fail the job;
  there is no ignored baseline or suppression file.
- `dependency-reports` artifacts retain the lockfile, sorted inventory, and
  available scan output for 14 days, including when scanning fails.
- A separate job submits the resolved dependency graph only from trusted main
  executions. It has `contents: write`; PR auditing has only `contents: read`.
  Enable Dependency graph and Dependabot alerts in repository settings to use
  GitHub's alert UI. OSV scanning does not depend on those settings.
- CI runs `JsonCompatibilityTest` and the full JWT/HTTP/CSRF/Swagger suite.
  `check` also runs `dependencyReport`. Publication is independent of these checks.

## Local checks and updates

```powershell
.\gradlew.bat dependencyReport
.\gradlew.bat dependencyInsight --configuration runtimeClasspath --dependency jackson
.\gradlew.bat clean build
```

`build/reports/dependencies/resolved-dependencies.json` lists sorted Maven
coordinates and configurations without timestamps or machine-specific paths.
Its contents can be compared across builds using the same lockfile.

For a local vulnerability scan, install
[OSV-Scanner 2.7.0](https://github.com/google/osv-scanner/releases/tag/v2.7.0), then run:

```powershell
osv-scanner scan source --lockfile=gradle.lockfile --format=json --output=build/reports/dependencies/osv.json
```

After deliberately changing a version in `build.gradle`, regenerate and review
the locks, then run the full build and vulnerability scan:

```powershell
.\gradlew.bat dependencyReport --write-locks
git diff -- build.gradle gradle.lockfile
.\gradlew.bat clean build
```

Review upgrades to Boot, springdoc, JJWT, and Jackson against their release notes
and the actual resolved versions. Assess findings against the package, affected
range, fixed version, and applicable code path, using the advisory's upstream
references. An old version number alone does not establish exploitability.
Regenerate the inventory and rescan after remediation.

## Jackson compatibility

Boot's HTTP mapper uses Jackson 3 (`tools.jackson.*`). JJWT's `jjwt-jackson`
adapter and springdoc's Swagger integration still resolve Jackson 2
(`com.fasterxml.jackson.*`); both implementation families are intentional.
Jackson annotations retain the `com.fasterxml.jackson.annotation` namespace,
which does not imply MVC is using Jackson 2 databind. See
[Boot's JSON documentation](https://docs.spring.io/spring-boot/reference/features/json.html)
and [JJWT's Jackson integration](https://github.com/jwtk/jjwt/tree/0.12.5#jackson-json-processor).

Jackson 2 is explicitly aligned through its BOM to **2.22.3** for the fixes below.
Boot's Jackson 3 family resolves to **3.1.7**. Excluding Jackson 2 would break the
JJWT adapter. `JsonCompatibilityTest` exercises HTTP request -> JWT generation ->
JWT validation -> authenticated HTTP response, preserving nested claims, numbers,
booleans, Unicode, and escaped strings. It verifies the HTTP mapper is Jackson 3
and the Jackson 2 adapter loads, and checks refresh-token purpose separation.

## Advisory review: November 9, 2026

The initial inventory contained **116 modules**. An OSV batch query of their exact
Maven coordinates returned seven advisories for Jackson 2 core/databind **2.22.1**.
Each linked advisory includes that resolved version in its affected range:

| Package | Advisory | Fix on the 2.22 line |
| --- | --- | --- |
| jackson-core | [GHSA-7hhh-6rmp-j9qf](https://github.com/advisories/GHSA-7hhh-6rmp-j9qf): unbounded invalid-token diagnostics | 2.22.3 |
| jackson-core | [GHSA-p6pp-m3f8-5c89](https://github.com/advisories/GHSA-p6pp-m3f8-5c89): numeric-pattern backtracking | 2.22.3 |
| jackson-databind | [GHSA-cxp5-3px4-pw24](https://github.com/advisories/GHSA-cxp5-3px4-pw24): quadratic forward-reference completion | 2.22.3 |
| jackson-databind | [GHSA-gx83-3vf8-gh7j](https://github.com/advisories/GHSA-gx83-3vf8-gh7j): polymorphic base-type validation | 2.22.2 |
| jackson-databind | [GHSA-q4xh-88c3-wmh7](https://github.com/advisories/GHSA-q4xh-88c3-wmh7): XML date/duration parsing limits | 2.22.2 |
| jackson-databind | [GHSA-wjgm-6hv5-3cvf](https://github.com/advisories/GHSA-wjgm-6hv5-3cvf): path provider resolution | 2.22.2 |
| jackson-databind | [GHSA-wv8q-qhhj-9h54](https://github.com/advisories/GHSA-wv8q-qhhj-9h54): unbounded unknown-type-ID cache | 2.22.3 |

Several findings require typed/polymorphic deserialization or particular parser
entry points; this does not establish an exploit in AutoAuth's plain claim maps.
Aligning the Jackson 2 BOM removes the affected versions throughout the resolved
family. A fresh OSV query then returned **zero findings for the 116 modules**.
That dated result is not a guarantee against future advisories; scheduled scans
recheck the committed lockfile against current data.

References: [Gradle locking](https://docs.gradle.org/9.0.0/userguide/dependency_locking.html),
[OSV lockfile support](https://google.github.io/osv-scanner/supported-languages-and-lockfiles/),
[Gradle graph submission](https://github.com/gradle/actions/blob/v6.4.1/docs/dependency-submission.md).
