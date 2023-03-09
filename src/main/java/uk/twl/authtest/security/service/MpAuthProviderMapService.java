package uk.twl.authtest.security.provider;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum MpAuthProviderMap {
    KC_AUTH_PROVIDER(KcAuthProvider.class),
    NIM_AUTH_PROVIDER(NimAuthProvider.class);

    private final Class<? extends AuthProvider> authProvider;
}
