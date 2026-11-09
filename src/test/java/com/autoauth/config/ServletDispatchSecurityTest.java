package com.autoauth.config;

import com.autoauth.annotation.*;
import com.autoauth.jwt.JwtGenerator;
import com.autoauth.model.AutoAuthUser;
import com.autoauth.support.TestKeys;
import com.autoauth.util.AuthContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.annotation.*;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URI;
import java.net.http.*;
import java.util.List;
import java.util.concurrent.Callable;

import static org.assertj.core.api.Assertions.assertThat;

/** Uses Tomcat: MockMvc does not execute real container forwards or error dispatches. */
@SpringBootTest(classes = ServletDispatchSecurityTest.App.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT, properties = {
        "server.servlet.context-path=/app",
        "autoauth.cookie-secure=false", "autoauth.public-paths[0]=/dispatch/**"})
class ServletDispatchSecurityTest {
    @Value("${local.server.port}") int port;
    @Autowired JwtGenerator generator;
    private final HttpClient client = HttpClient.newHttpClient();

    @DynamicPropertySource static void keys(DynamicPropertyRegistry registry) {
        registry.add("autoauth.private-key", () -> TestKeys.properties().getPrivateKey());
    }

    @Test void contextPathInheritedAliasesAndHttpMethodsKeepTheirBoundaries() throws Exception {
        for (String path : List.of("/open", "/alias")) {
            assertThat(send(path, "GET", null).statusCode()).isEqualTo(200);
            assertThat(send(path, "HEAD", null).statusCode()).isEqualTo(200);
            assertThat(send(path, "POST", null).statusCode()).isEqualTo(403);
            assertThat(postWithCsrf(path).statusCode()).isEqualTo(401);
            assertThat(send(path, "OPTIONS", null).statusCode()).isEqualTo(401);
        }
        assertThat(send("/secured/user", "GET", null).statusCode()).isEqualTo(401);
        assertThat(send("/secured/user", "GET", "USER").body()).isEqualTo("alice");
        assertThat(send("/open-options", "OPTIONS", null).statusCode()).isEqualTo(200);
        assertThat(send("/unmapped", "GET", null).statusCode()).isEqualTo(401);
    }

    @Test void forwardsReauthorizeTheTargetAndEnforceRoles() throws Exception {
        assertThat(send("/dispatch/forward?target=/secured/plain", "GET", null).statusCode()).isEqualTo(401);
        assertThat(send("/dispatch/forward?target=/secured/user", "GET", null).statusCode()).isEqualTo(401);
        assertThat(send("/dispatch/forward?target=/secured/user", "GET", "USER").body()).isEqualTo("alice");
        assertThat(send("/dispatch/forward?target=/secured/admin", "GET", "USER").statusCode()).isEqualTo(403);
        assertThat(send("/dispatch/forward?target=/secured/admin", "GET", "ADMIN").body()).isEqualTo("admin");
        assertThat(send("/mvc-forward?target=/secured/user", "GET", null).statusCode()).isEqualTo(401);
        assertThat(send("/mvc-forward?target=/secured/plain", "GET", null).statusCode()).isEqualTo(401);
        assertThat(send("/mvc-forward?target=/secured/admin", "GET", "USER").statusCode()).isEqualTo(403);
        assertThat(send("/mvc-forward?target=/secured/admin", "GET", "ADMIN").body()).isEqualTo("admin");
    }

    @Test void asyncDispatchReauthorizesTheTargetAndPreservesAuthenticatedContinuations() throws Exception {
        assertThat(send("/dispatch/async?target=/secured/plain", "GET", null).statusCode()).isEqualTo(401);
        assertThat(send("/dispatch/async?target=/secured/user", "GET", null).statusCode()).isEqualTo(401);
        assertThat(send("/dispatch/async?target=/secured/admin", "GET", "USER").statusCode()).isEqualTo(403);
        assertThat(send("/dispatch/async?target=/secured/admin", "GET", "ADMIN").body()).isEqualTo("admin");
        assertThat(send("/secured/async", "GET", "USER").body()).isEqualTo("alice");
    }

    @Test void errorDispatchDoesNotExposeAProtectedErrorHandler() throws Exception {
        assertThat(send("/dispatch/error", "GET", null).statusCode()).isEqualTo(401);
        assertThat(send("/dispatch/error", "GET", null).body()).doesNotContain("protected error");
        assertThat(send("/dispatch/error", "GET", "USER").statusCode()).isEqualTo(403);
        var authorized = send("/dispatch/error", "GET", "ADMIN");
        assertThat(authorized.statusCode()).isEqualTo(500);
        assertThat(authorized.body()).isEqualTo("protected error");
    }

    @Test void cookieCredentialsAlsoAuthenticateAsyncAndErrorDispatches() throws Exception {
        String cookie = "AUTOAUTH=" + generator.generateAccessToken(new AutoAuthUser("alice", List.of("ADMIN"), null));
        for (String path : List.of("/dispatch/async?target=/secured/admin", "/dispatch/forward?target=/secured/admin")) {
            var response = client.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/app" + path))
                    .timeout(java.time.Duration.ofSeconds(10)).header("Cookie", cookie).build(), HttpResponse.BodyHandlers.ofString());
            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(response.body()).isEqualTo("admin");
        }
        var error = client.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/app/dispatch/error"))
                .timeout(java.time.Duration.ofSeconds(10)).header("Cookie", cookie).build(), HttpResponse.BodyHandlers.ofString());
        assertThat(error.statusCode()).isEqualTo(500);
        assertThat(error.body()).isEqualTo("protected error");
    }

    private HttpResponse<String> send(String path, String method, String role) throws Exception {
        var request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/app" + path))
                .timeout(java.time.Duration.ofSeconds(10)).method(method, HttpRequest.BodyPublishers.noBody());
        if (role != null) request.header("Authorization", "Bearer " + generator.generateAccessToken(
                new AutoAuthUser("alice", List.of(role), null)));
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> postWithCsrf(String path) throws Exception {
        var bootstrap = send("/autoauth/csrf", "GET", null);
        assertThat(bootstrap.statusCode()).isEqualTo(200);
        String cookie = bootstrap.headers().allValues("Set-Cookie").stream()
                .filter(value -> value.startsWith("XSRF-TOKEN=")).findFirst().orElseThrow().split(";", 2)[0];
        return client.send(HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/app" + path))
                .timeout(java.time.Duration.ofSeconds(10)).header("Cookie", cookie)
                .header("X-XSRF-TOKEN", cookie.substring("XSRF-TOKEN=".length()))
                .POST(HttpRequest.BodyPublishers.noBody()).build(), HttpResponse.BodyHandlers.ofString());
    }

    @Configuration(proxyBeanMethods = false) @EnableAutoConfiguration @Import(Routes.class)
    static class App {
        @Bean ServletRegistrationBean<HttpServlet> dispatchServlet() {
            var registration = new ServletRegistrationBean<HttpServlet>(new HttpServlet() {
                @Override protected void doGet(HttpServletRequest request, HttpServletResponse response)
                        throws ServletException, IOException {
                    switch (request.getPathInfo()) {
                        case "/forward" -> request.getRequestDispatcher(request.getParameter("target")).forward(request, response);
                        case "/async" -> request.startAsync().dispatch(request.getParameter("target"));
                        case "/error" -> response.sendError(500);
                        default -> response.sendError(404);
                    }
                }
            }, "/dispatch/*");
            registration.setAsyncSupported(true);
            return registration;
        }
    }
    public static class ParentRoutes {
        @PublicEndpoint @GetMapping(path = {"/open", "/alias"}) public String open() { return "public"; }
    }
    @RestController public static class Routes extends ParentRoutes implements org.springframework.boot.webmvc.error.ErrorController {
        @PublicEndpoint @GetMapping("/mvc-forward") public void forward(HttpServletRequest request, HttpServletResponse response)
                throws ServletException, IOException {
            request.getRequestDispatcher(request.getParameter("target")).forward(request, response);
        }
        @PostMapping("/open") public String post() { return "protected post"; }
        @PublicEndpoint @RequestMapping(path = "/open-options", method = RequestMethod.OPTIONS)
        public String publicOptions() { return "explicit public options"; }
        @GetMapping("/secured/user") public String user() { return AuthContext.getCurrentUserId().orElseThrow(); }
        @GetMapping("/secured/plain") public String plain() { return "protected response"; }
        @RequiresRole("ADMIN") @GetMapping("/secured/admin") public String admin() { return "admin"; }
        @GetMapping("/secured/async") public Callable<String> async() {
            return () -> AuthContext.getCurrentUserId().orElseThrow();
        }
        @RequiresRole("ADMIN") @RequestMapping("/error") public String error() { return "protected error"; }
    }
}
