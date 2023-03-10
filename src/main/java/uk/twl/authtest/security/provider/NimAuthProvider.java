package uk.twl.authtest.security.provider;

import java.util.Map;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

@Component
@RequiredArgsConstructor
@Slf4j
public class NimAuthProvider implements AuthProvider {

  @Override
  public String getName() {
    return NimAuthProvider.class.getSimpleName();
  }

  @Override
  public MultiValueMap<String, String> authenticate(String username, String password) {
    // TODO: implement Nim authentication
    return new LinkedMultiValueMap<>(Map.of());
  }

  @Override
  public boolean authenticate(HttpServletRequest request) {
    // TODO: implement Nim authorisation

    log.info("NimAuthProvider.authenticate() called");
    return true;
  }

  @Override
  public UUID getUserId(MultiValueMap<String, String> headers) {
    // TODO: implement getting Nim UserId
    return null;
  }
}
