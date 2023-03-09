package uk.twl.authtest.security.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import uk.twl.authtest.security.controller.request.JwtRequest;
import uk.twl.authtest.security.controller.request.JwtResponse;
import uk.twl.authtest.security.provider.MpAuthProvider;
import uk.twl.authtest.security.provider.MpTokenProvider;

import java.util.Map;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
public class JwtAuthenticationController {
    private final MpTokenProvider mpTokenProvider;

    @PostMapping(value = "/authenticate")
    public ResponseEntity<JwtResponse> createAuthenticationToken(@RequestBody JwtRequest authenticationRequest) throws Exception {

        String username = authenticationRequest.getUsername();
        String password = authenticationRequest.getPassword();
        MpAuthProvider authProvider = authenticationRequest.getMpAuthProvider();
        Map<String, String> authProviderHeader  = authProvider.authenticate(username, password);
        UUID userId  = authProvider.getUserId(authProviderHeader);


        final Map<String, String> serviceHeader = mpTokenProvider.generateToken(userId, false, authProvider);

        JwtResponse jwtResponse = JwtResponse.builder()
            .serviceHeader(serviceHeader)
            .authProviderHeader(authProviderHeader)
            .build();

        return ResponseEntity.ok(jwtResponse);
    }
}
