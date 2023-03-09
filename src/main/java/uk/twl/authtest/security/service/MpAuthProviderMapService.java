package uk.twl.authtest.security.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import uk.twl.authtest.security.provider.AuthProvider;
import uk.twl.authtest.security.provider.KcAuthProvider;
import uk.twl.authtest.security.provider.MpAuthProviderMap;

import java.util.List;

@Service
@RequiredArgsConstructor
public class MpAuthProviderMapService {
    private final List<KcAuthProvider> list;

    public AuthProvider getAuthProvider(MpAuthProviderMap authProviderMap) {
        return list.stream()
                .filter(authProvider -> authProvider.getClass().equals(authProviderMap.getAuthProvider()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("AuthProvider not found"));
    }
}
