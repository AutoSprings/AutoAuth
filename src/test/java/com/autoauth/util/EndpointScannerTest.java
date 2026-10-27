package com.autoauth.util;

import com.autoauth.annotation.PublicEndpoint;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.web.bind.annotation.*;

import static org.assertj.core.api.Assertions.assertThat;

class EndpointScannerTest {
    @Test
    void findsPublicMethodsAndClassesAcrossBasePaths() {
        try (var context = new AnnotationConfigApplicationContext()) {
            context.register(MixedController.class, PublicController.class, RootController.class);
            context.refresh();
            assertThat(new EndpointScanner(context).getPublicPaths()).containsExactlyInAnyOrder(
                    "/api/open", "/api/status", "/v2/open", "/v2/status",
                    "/api", "/v2", "/public/**", "/health");
        }
    }

    @Test
    void noControllersProducesNoPublicPaths() {
        try (var context = new AnnotationConfigApplicationContext()) {
            context.refresh();
            assertThat(new EndpointScanner(context).getPublicPaths()).isEmpty();
        }
    }

    @RestController
    @RequestMapping({"/api", "/v2"})
    static class MixedController {
        @PublicEndpoint @GetMapping({"/open", "/status"}) public void open() {}
        @PublicEndpoint @GetMapping public void index() {}
        @GetMapping("/private") public void secured() {}
    }

    @PublicEndpoint @RestController @RequestMapping("/public/")
    static class PublicController {
        @GetMapping("/any") public void any() {}
    }

    @RestController
    static class RootController {
        @PublicEndpoint @GetMapping("/health") public void health() {}
    }
}
