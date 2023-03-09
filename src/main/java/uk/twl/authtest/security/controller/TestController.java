package uk.twl.authtest.security.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import uk.twl.authtest.security.controller.request.AuthenticationRequest;
import uk.twl.authtest.security.provider.MpAuthProvider;
import uk.twl.authtest.security.provider.ServiceAuthProvider;

import java.util.List;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
public class AuthenticationController {
    private final ServiceAuthProvider serviceAuthProvider;

    @PostMapping(value = "/auth/authenticate")
    public ResponseEntity createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) {

        String username = authenticationRequest.getUsername();
        String password = authenticationRequest.getPassword();
        MpAuthProvider authProvider = authenticationRequest.getMpAuthProvider();
        MultiValueMap<String, String> authProviderHeaders  = authProvider.authenticate(username, password);
        UUID userId  = authProvider.getUserId(authProviderHeaders);

        HttpHeaders responseHeaders = new HttpHeaders();

        responseHeaders.addAll(new LinkedMultiValueMap<>(authProviderHeaders));

        final String serviceHeaderValue = serviceAuthProvider.generateBearerToken(userId, false, authProvider);
        final String serviceHeaderName = serviceAuthProvider.getHeaderName();

        responseHeaders.put(serviceHeaderName, List.of(serviceHeaderValue));

        return ResponseEntity.ok().headers(responseHeaders).build();
    }
}
