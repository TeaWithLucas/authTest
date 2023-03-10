package uk.twl.authtest.security.service;

import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import uk.twl.authtest.security.provider.AuthProvider;
import uk.twl.authtest.security.provider.MpAuthProviderMap;

@Service
@RequiredArgsConstructor
public class MpAuthProviderMapService {
  private final List<AuthProvider> list;

  public AuthProvider getAuthProvider(MpAuthProviderMap authProviderMap) {
    return list.stream()
        .filter(authProvider -> authProvider.getClass().equals(authProviderMap.getAuthProvider()))
        .findFirst()
        .orElseThrow(() -> new RuntimeException("AuthProvider not found"));
  }
}
