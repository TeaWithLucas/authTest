package uk.twl.authtest.security.provider;

import java.util.Arrays;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum MpAuthProviderMap {
    KC_AUTH_PROVIDER(KcAuthProvider.class, true),
    NIM_AUTH_PROVIDER(NimAuthProvider.class, false);

    private final Class<? extends AuthProvider> authProvider;
    private final boolean isEnabled;

    public static MpAuthProviderMap getAuthProviderMap(String name) {
        return Arrays.stream(MpAuthProviderMap.values())
            .filter(providerMap -> providerMap.name().equalsIgnoreCase(name))
            .findFirst()
            .orElse(null);
    }
}
