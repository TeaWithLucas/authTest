package uk.twl.authtest.security.controller;

import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import uk.twl.authtest.security.controller.request.AuthenticationRequest;
import uk.twl.authtest.security.provider.AuthProvider;
import uk.twl.authtest.security.provider.MpAuthProviderMap;
import uk.twl.authtest.security.provider.ServiceAuthProvider;
import uk.twl.authtest.security.service.MpAuthProviderMapService;

@RestController
@RequiredArgsConstructor
@Slf4j
public class AuthenticationController {

  private final MpAuthProviderMapService authProviderMapService;
  private final ServiceAuthProvider serviceAuthProvider;

  @PostMapping(value = "/auth/authenticate")
  public ResponseEntity createAuthenticationToken(@RequestBody AuthenticationRequest authenticationRequest) {

    String username = authenticationRequest.getUsername();
    String password = authenticationRequest.getPassword();
    MpAuthProviderMap authProviderMap = authenticationRequest.getAuthProvider();

    AuthProvider authProvider = authProviderMapService.getAuthProvider(authProviderMap);

    if (!authProviderMap.isEnabled()) {
      log.error("authProvider {} is not enabled", authProviderMap);
      throw new RuntimeException("authProvider is not enabled");
    }

    MultiValueMap<String, String> authProviderHeaders  = authProvider.authenticate(username, password);
    UUID userId  = authProvider.getUserId(authProviderHeaders);

    HttpHeaders responseHeaders = new HttpHeaders();

    responseHeaders.addAll(new LinkedMultiValueMap<>(authProviderHeaders));

    final String serviceHeaderValue = serviceAuthProvider.generateBearerToken(userId, false, authProviderMap);
    final String serviceHeaderName = serviceAuthProvider.getHeaderName();

    responseHeaders.put(serviceHeaderName, List.of(serviceHeaderValue));

    return ResponseEntity.ok().headers(responseHeaders).build();
  }
}
