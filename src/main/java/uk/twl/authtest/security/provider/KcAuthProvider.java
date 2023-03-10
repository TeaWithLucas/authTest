package uk.twl.authtest.security.provider;

import static org.springframework.util.ObjectUtils.isEmpty;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * This class provides authentication functionality by integrating with a Keycloak Manager to authenticate users and retrieve user information.
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class KcAuthProvider implements AuthProvider {
  /**
   * The name of the authorization header containing the user token.
   */
  @Value("${jwt.userAuthorisationHeaderName}")
  private final String userAuthorisationHeaderName;

  /**
   * The BearerTokenResolver used to resolve the user token.
   */
  @Qualifier("userBearerTokenResolver")
  public final BearerTokenResolver userBearerTokenResolver;

  @Override
  public String getName() {
    return KcAuthProvider.class.getSimpleName();
  }

  /**
   * Authenticates a user based on the provided username and password, using the Keycloak Manager to obtain a token.
   *
   * @param username the username of the user
   * @param password the password of the user
   * @return a {@link MultiValueMap} containing the user information, including the authentication token
   */
  @Override
  public MultiValueMap<String, String> authenticate(String username, String password) {
    // TODO get token from KcManagerApi
    String token = "sdfsdfsd.sdfsdfsd.sdfsdfsd";
    return new LinkedMultiValueMap<>(Map.of(
        userAuthorisationHeaderName,
        List.of("Bearer " + token))
    );
  }

  /**
   * Authenticates a user based on the provided {@link HttpServletRequest}, using the userBearerTokenResolver to extract the user token and the Keycloak server to validate it.
   *
   * @param request the {@link HttpServletRequest} object containing the user information
   * @return true if the user is authenticated, false otherwise
   */
  @Override
  public boolean authenticate(HttpServletRequest request) {

    final String userAuthorisationToken = userBearerTokenResolver.resolve(request);


    if (isEmpty(userAuthorisationToken)) {
      log.info("User token is {}", userAuthorisationToken);
      return false;
    }

    // TODO: call KcManagerApi to validate the token

    return true;
  }

  /**
   * Returns the user ID based on the provided headers, using the Keycloak Manager to retrieve the user ID.
   *
   * @param headers a {@link MultiValueMap} containing the headers of the user request
   * @return the user ID as a {@link UUID}
   */
  @Override
  public UUID getUserId(MultiValueMap<String, String> headers) {
    // TODO get userId from KcManagerApi
    return UUID.randomUUID();
  }

}
