"""Verify the staged Maven and Gradle artifacts using independent runnable consumers."""
import argparse
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def run(command):
    subprocess.run([str(value) for value in command], cwd=ROOT, check=True)


def maven_command():
    installed = shutil.which("mvn")
    if installed:
        return installed
    # Keep the optional tool download inside ignored build output; verify Apache's checksum.
    version = "3.9.16"
    tools = ROOT / "build" / "tools"
    executable = tools / f"apache-maven-{version}" / "bin" / ("mvn.cmd" if os.name == "nt" else "mvn")
    if not executable.exists():
        tools.mkdir(parents=True, exist_ok=True)
        url = f"https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/{version}/apache-maven-{version}-bin.zip"
        checksum = urllib.request.urlopen(url + ".sha512", timeout=60).read().decode().split()[0]
        archive = tools / f"apache-maven-{version}-bin.zip"
        with urllib.request.urlopen(url, timeout=60) as response, archive.open("wb") as output:
            shutil.copyfileobj(response, output)
        if hashlib.sha512(archive.read_bytes()).hexdigest().lower() != checksum.lower():
            raise RuntimeError("Maven download checksum mismatch")
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.namelist():
                if not (tools / member).resolve().is_relative_to(tools.resolve()):
                    raise RuntimeError("Unsafe path in Maven archive")
            bundle.extractall(tools)
        if os.name != "nt":
            executable.chmod(0o755)
    return executable


def verify_metadata(repository, group, version):
    directory = repository / group.replace(".", "/") / "autoauth" / version
    # File repositories timestamp SNAPSHOT filenames just like remote repositories.
    pom_file = max(directory.glob('autoauth-*.pom'), key=lambda path: path.stat().st_mtime_ns)
    stem = pom_file.stem
    namespace = {"m": "http://maven.apache.org/POM/4.0.0"}
    pom = ET.parse(pom_file).getroot()
    for field in ("name", "description", "url", "licenses/license/name", "developers/developer/id", "scm/connection"):
        element = pom.find("m:" + field.replace("/", "/m:"), namespace)
        assert element is not None and element.text, f"Missing POM metadata: {field}"
    metadata = json.loads((directory / (stem + ".module")).read_text())
    api = next(variant for variant in metadata["variants"] if variant["name"] == "apiElements")
    assert any(dependency["module"] == "spring-boot-dependencies" for dependency in api["dependencies"]), "API variant lost its BOM"
    for suffix in (".jar", "-sources.jar", "-javadoc.jar"):
        with zipfile.ZipFile(directory / (stem + suffix)) as artifact:
            assert "META-INF/LICENSE" in artifact.namelist(), f"License missing from {suffix}"


def verify_maven_runtime(example):
    # The repackaged application's actual JARs must match the patched library baseline.
    inventory = json.loads((ROOT / "build" / "reports" / "dependencies" / "resolved-dependencies.json").read_text())
    with zipfile.ZipFile(example / "target" / "cookie-consumer-1.0.0.jar") as application:
        libraries = {Path(name).name for name in application.namelist() if name.startswith("BOOT-INF/lib/")}
    for dependency in inventory["dependencies"]:
        if dependency["group"] == "com.fasterxml.jackson.core" or dependency["name"] in (
                "spring-boot", "spring-core", "spring-security-core", "jackson-databind"):
            expected = f"{dependency['name']}-{dependency['version']}.jar"
            assert expected in libraries, f"Maven consumer lost baseline alignment: {expected}"


def smoke(command, label):
    with socket.socket() as connection:
        connection.bind(("127.0.0.1", 0))
        port = connection.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

    def request(path, expected=200, data=None, csrf=None):
        headers = {}
        if data is not None:
            data = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        if csrf is not None:
            # Authentication can rotate CSRF state; bootstrap the current cookie/header pair.
            current_csrf = json.loads(request("/autoauth/csrf")[0])
            headers[current_csrf["headerName"]] = current_csrf["token"]
        message = urllib.request.Request(base + path, data=data, headers=headers)
        try:
            response = client.open(message, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read().decode()
            assert response.status == expected, f"{label}: {path}: expected {expected}, got {response.status}: {body}"
            return body, response.headers

    reports = ROOT / "build" / "reports" / "publication"
    reports.mkdir(parents=True, exist_ok=True)
    with (reports / f"{label}.log").open("w") as log:
        process = subprocess.Popen([str(value) for value in command] + [f"--server.port={port}"], cwd=ROOT,
                                   stdout=log, stderr=subprocess.STDOUT,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        try:
            deadline = time.monotonic() + 90
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f"{label} exited; inspect {log.name}")
                try:
                    csrf = json.loads(request("/autoauth/csrf")[0])
                    break
                except (urllib.error.URLError, TimeoutError):
                    if time.monotonic() >= deadline:
                        raise RuntimeError(f"{label} startup timed out; inspect {log.name}")
                    time.sleep(0.25)
            request("/me", 401)
            credentials = {"username": "alice", "password": "demo-only"}
            request("/login", 403, credentials)
            request("/login", 401, {**credentials, "password": "wrong"}, csrf)
            _, headers = request("/login", data=credentials, csrf=csrf)
            for name in ("AUTOAUTH=", "AUTOAUTH_REFRESH="):
                cookie = next(value for value in headers.get_all("Set-Cookie") if value.startswith(name))
                assert "HttpOnly" in cookie and "SameSite=Lax" in cookie
            assert json.loads(request("/me")[0])["userId"] == "alice"
            request("/admin", 403)
            access = next(cookie for cookie in jar if cookie.name == "AUTOAUTH")
            refresh = next(cookie for cookie in jar if cookie.name == "AUTOAUTH_REFRESH")
            original_refresh = refresh.value
            refresh.value = "malformed"
            request("/refresh", 401, {}, csrf)
            refresh.value = original_refresh
            # A refresh cookie alone must not authenticate protected routes, but can renew a pair.
            jar.clear(access.domain, access.path, access.name)
            request("/me", 401)
            request("/refresh", data={}, csrf=csrf)
            assert next(cookie.value for cookie in jar if cookie.name == "AUTOAUTH_REFRESH") != original_refresh
            assert json.loads(request("/me")[0])["roles"] == ["USER"]
            document = json.loads(request("/v3/api-docs")[0])
            assert document["info"]["title"] == "AutoAuth cookie example"
            assert document["components"]["securitySchemes"]["JWT-Bearer"]["scheme"] == "bearer"
            request("/swagger-ui/index.html")
            assert "X-XSRF-TOKEN" in request("/swagger-ui/swagger-initializer.js")[0]
            request("/logout", data={}, csrf=csrf)
            assert not any(cookie.name in ("AUTOAUTH", "AUTOAUTH_REFRESH") for cookie in jar)
            request("/me", 401)
            request("/login", data={"username": "admin", "password": "demo-only"}, csrf=csrf)
            request("/admin")
            print(f"{label}: published artifact passed login, CSRF, cookies, access, roles, refresh, logout, and Swagger")
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--group", default="io.github.autosprings")
    parser.add_argument("--version", default="1.0.0")
    parser.add_argument("--gradle-user-home")
    args = parser.parse_args()
    gradle = [ROOT / "gradlew.bat"] if os.name == "nt" else ["bash", ROOT / "gradlew"]
    if args.gradle_user_home:
        gradle += ["--gradle-user-home", args.gradle_user_home]
    coordinates = [f"-PpublicationGroup={args.group}", f"-PreleaseVersion={args.version}"]
    run(gradle + coordinates + ["dependencyReport", "publishMavenJavaPublicationToStagingRepository", "--console=plain"])
    repository = ROOT / "build" / "staging-repository"
    verify_metadata(repository, args.group, args.version)
    example = ROOT / "examples" / "cookie-consumer"
    run(gradle + ["-p", example, f"-PautoauthRepository={repository.as_uri()}",
                  f"-PautoauthGroup={args.group}", f"-PautoauthVersion={args.version}", "clean", "installDist", "--console=plain"])
    java = Path(os.environ["JAVA_HOME"]) / "bin" / "java" if os.environ.get("JAVA_HOME") else "java"
    smoke([java, "-cp", example / "build" / "install" / "cookie-consumer" / "lib" / "*", "demo.DemoApplication"], "gradle")
    run([maven_command(), "-B", "-ntp", "-U", "-f", example / "pom.xml", f"-Dautoauth.repository={repository.as_uri()}",
         f"-Dautoauth.group={args.group}", f"-Dautoauth.version={args.version}",
         f"-Dmaven.repo.local={ROOT / 'build' / 'maven-consumer-cache'}", "clean", "package"])
    verify_maven_runtime(example)
    smoke([java, "-jar", example / "target" / "cookie-consumer-1.0.0.jar"], "maven")


if __name__ == "__main__":
    main()
