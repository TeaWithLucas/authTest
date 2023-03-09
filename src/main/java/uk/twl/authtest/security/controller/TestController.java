package uk.twl.authtest.security.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import uk.twl.authtest.security.provider.ServiceAuthProvider;

@RestController
@RequiredArgsConstructor
public class TestController {
    private final ServiceAuthProvider serviceAuthProvider;

    @GetMapping(value = "/test")
    public ResponseEntity<String> createAuthenticationToken() {

        return ResponseEntity.ok("test");
    }
}
