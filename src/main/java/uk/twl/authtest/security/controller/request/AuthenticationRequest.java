package uk.twl.authtest.security.controller.request;

import lombok.Data;
import org.springframework.lang.NonNull;
import uk.twl.authtest.security.provider.MpAuthProviderMap;

@Data
public class AuthenticationRequest {
  @NonNull
  private final String username;
  @NonNull
  private final String password;
  @NonNull
  private final MpAuthProviderMap authProvider;
}
