# Publish AutoAuth to Maven Central

AutoAuth builds with **Gradle** and publishes a Maven-compatible artifact.
Maven Central is the repository; you do not need to convert the library to Maven.
Publish directly with Gradle using existing Portal credentials, or prepare a signed
ZIP and publish it through the Central Portal. Both paths use the same publication.

## Existing local Gradle credentials

You can reuse a valid signing key and active Portal token from a previous release.
The build reads these properties from your user-level `~/.gradle/gradle.properties`:

```properties
mavenCentralUsername=YOUR_PORTAL_TOKEN_USERNAME
mavenCentralPassword=YOUR_PORTAL_TOKEN_PASSWORD
signingInMemoryKey=YOUR_EXISTING_ARMORED_PRIVATE_KEY
signingInMemoryKeyPassword=YOUR_EXISTING_KEY_PASSPHRASE
```

Keep the real values in that user file, not in this checkout. These are Portal
user-token credentials, not your website login password. Expired/revoked tokens
must be replaced; existing working tokens and signing keys need not be regenerated.
The `SIGNING_KEY`/`SIGNING_PASSWORD` environment variables can override the local
signing properties (for example in CI).

After choosing an unused release version and confirming namespace ownership,
upload from this computer with:

```powershell
.\gradlew.bat '-PpublicationGroup=com.autoauth' '-PreleaseVersion=2.0.0' publishToMavenCentral
```

This runs checks, signs, and uploads; finish by choosing **Publish** in the Portal.
To upload, validate, and publish entirely from Gradle instead, use:

```powershell
.\gradlew.bat '-PpublicationGroup=com.autoauth' '-PreleaseVersion=2.0.0' publishAndReleaseToMavenCentral
```

The second command publishes the release to Central. Replace both example
coordinates with the intended verified group and unused version. Run the consumer
verification in step 4 first and use the exact tested release commit.
The existing local user-home override may also be supplied as described below.
Plugin documentation: <https://vanniktech.github.io/gradle-maven-publish-plugin/central/>.

The remaining steps explain first-time account/key setup and the optional manual
ZIP workflow. Skip setup you already completed.

## 1. Choose and verify the namespace

Sign in at <https://central.sonatype.com/> and open Namespaces.
Keep `com.autoauth` only if that namespace is verified for your publishing account.
Otherwise verify a namespace you control (for example an eligible
`io.github.<account>` namespace). Java packages need not change when the Maven
group changes. Supply the chosen group with `-PpublicationGroup=...` on **every**
verification and bundle command.

See <https://central.sonatype.org/register/namespace/> for account/domain or
GitHub verification. This repository cannot verify account ownership for you.

## 2. Select an unused version

The development default is `1.0.3-SNAPSHOT`. Bundles require an explicit release
version, for example `-PreleaseVersion=2.0.0`. A new major release is appropriate
if updating existing published consumers to the breaking Boot 4/API baseline.
Confirm the chosen coordinates have not already been released: Central artifacts
are immutable. Use the same group/version for verification, bundle, release notes,
and the eventual Git tag.

## 3. Create a signing key

Install GnuPG (Gpg4win on Windows), then run in your terminal:

```powershell
gpg --full-generate-key
gpg --list-secret-keys --keyid-format LONG
```

Choose an RSA signing-capable key of at least 3072 bits and protect it with a
passphrase. Record the **full fingerprint**. Publish its public key:

```powershell
gpg --keyserver keyserver.ubuntu.com --send-keys YOUR_FULL_FINGERPRINT
```

Confirm the public key can be retrieved before uploading artifacts. Keep the
private key and passphrase outside the repository. Official instructions:
<https://central.sonatype.org/publish/requirements/gpg/>.

## 4. Verify the release artifact

Use Java 21 and Python 3.11+. From a clean release checkout:

```powershell
.\gradlew.bat clean build
python scripts/verify-publication.py --group com.autoauth --version 2.0.0
```

Replace the example coordinates with your verified group and chosen version.
The verifier stages the artifact, checks POM/Gradle metadata and license packaging,
builds independent Gradle and Maven consumers, and tests their running HTTP flows.
It downloads Maven to ignored build output if needed. It does not upload anything.
Ensure GitHub CI and the dependency audit also pass for the release commit.

## 5. Build the signed upload bundle

Load the private key directly into the current PowerShell process. Do not paste
the private key or passphrase into chat, command arguments, source files, or logs.

```powershell
$env:SIGNING_KEY = (gpg --armor --export-secret-keys YOUR_FULL_FINGERPRINT) -join "`n"
$signingPassphrase = Read-Host 'Signing key passphrase' -AsSecureString
$signingCredential = [System.Net.NetworkCredential]::new('', $signingPassphrase)
$env:SIGNING_PASSWORD = $signingCredential.Password
try {
    .\gradlew.bat '-PpublicationGroup=com.autoauth' '-PreleaseVersion=2.0.0' centralBundle
    if ($LASTEXITCODE -ne 0) { throw 'Release bundle failed' }
} finally {
    Remove-Item Env:SIGNING_KEY, Env:SIGNING_PASSWORD -ErrorAction SilentlyContinue
    Remove-Variable signingPassphrase, signingCredential -ErrorAction SilentlyContinue
}
```

GnuPG may ask for the passphrase when exporting; the build also needs it to sign.
Use the same selected coordinates here. The task checks the version/signing inputs,
runs checks/tests, stages signed JARs, POM, Gradle metadata, and checksums, then
creates `build/central/autoauth-2.0.0-central.zip`.
Sources, Javadoc, and the MIT license are included. Inspect the ZIP and verify a
signature locally with `gpg --verify <file>.asc <file>` if you extract it.

## 6. Upload, validate, and publish

1. Sign in to <https://central.sonatype.com/>.
2. Open the publishing/deployments page and choose **Publish Component**.
3. Upload the ZIP from `build/central` and give the deployment a useful name.
4. Wait for validation. Address every error before publication: common causes are
   namespace ownership, missing public signing keys, and invalid signatures.
5. Inspect the validated coordinates and artifacts, then choose **Publish**.
6. Wait for the deployment to show **Published** and for repository propagation.

Upload the inner `autoauth-...-central.zip`, not a GitHub Actions artifact wrapper.
Official Portal upload guide: <https://central.sonatype.org/publish/publish-portal-upload/>.

## 7. Check installation and tag the release

Check a fresh application resolves the chosen coordinates from `mavenCentral()`
or Maven's default Central repository, with no staging repository or `mavenLocal()`.
Run the cookie example against Central by omitting the staging repository option:

```powershell
mvn -f examples/cookie-consumer/pom.xml '-Dautoauth.group=com.autoauth' '-Dautoauth.version=2.0.0' package
```

After successful publication, tag the exact tested commit (`v2.0.0` for the example)
and publish release notes with coordinates, Java/Boot requirements, and migration
links. Update the README installation snippet to the actual released coordinates.
Do not reuse a published version if a correction is needed; release a new version.

## Optional GitHub Actions bundle preparation

Create a GitHub environment named `maven-central`, and store `SIGNING_KEY`
(ASCII-armored secret key) and `SIGNING_PASSWORD` as its secrets. The repository's
**Prepare Central release bundle** workflow accepts group/version inputs, builds
and tests, verifies both consumers, audits the lockfile, and uploads the signed ZIP
as an Actions artifact. It never publishes to Central. Download and unzip the
Actions artifact, then follow step 6 with the inner ZIP.

Run the workflow from the exact commit intended for release. User-supplied inputs
are passed through environment variables rather than interpolated shell code.
To export the secret key for entry into GitHub's secret field, use an output file
outside this checkout, for example:

```powershell
gpg --armor --output "$env:TEMP/autoauth-release-key.asc" --export-secret-keys YOUR_FULL_FINGERPRINT
```

Copy that file's contents into the environment secret, then remove the exported
copy after confirming the secret is saved. Do not use the disposable offline test
key or test ZIP under `build`; those are packaging diagnostics, not release artifacts.

## Local build cache

If your Windows shell points Gradle at an unexpected user home, add
`--gradle-user-home C:/Users/YOUR_USER/.gradle` to Gradle commands and pass the same
option to the Python verifier. Build outputs, staged repositories, consumer caches,
and downloaded tools are ignored by Git.
