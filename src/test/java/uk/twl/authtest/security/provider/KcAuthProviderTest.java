package uk.twl.authtest.security.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.BDDMockito.given;

import java.util.List;
import java.util.Map.Entry;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

@ExtendWith(MockitoExtension.class)
@DisplayName("Kc Auth Provider Unit Tests")
class KcAuthProviderTest {

  public static final String USERNAME = "test";
  public static final String PASSWORD = "test123";
  private KcAuthProvider kcAuthProvider;

  @Mock
  private BearerTokenResolver userBearerTokenResolver;
  @Mock
  private HttpServletRequest httpServletRequest;

  private static String HEADER_NAME = "testHeader";

  @BeforeEach
  void setUp() {
    kcAuthProvider = new KcAuthProvider(HEADER_NAME, userBearerTokenResolver);
  }


  @Test
  @DisplayName("Test authenticate method with valid username and password")
  void testAuthenticateWithValidUsernameAndPassword() {
    // Given / When
    MultiValueMap<String, String> result = kcAuthProvider.authenticate(USERNAME, PASSWORD);

    // Then
    assertThat(result)
        .hasSize(1)
        .extractingFromEntries(Entry::getKey, Entry::getValue)
        .containsOnly(tuple(HEADER_NAME, List.of("Bearer sdfsdfsd.sdfsdfsd.sdfsdfsd")));
  }


  @Test
  @DisplayName("Test authenticate method with null username and password")
  void testAuthenticateWithNullUsernameAndPassword() {
    // Given / When
    MultiValueMap<String, String> result = kcAuthProvider.authenticate(null, null);

    // Then
    assertThat(result)
        .hasSize(1)
        .extractingFromEntries(Entry::getKey, Entry::getValue)
        .containsOnly(tuple(HEADER_NAME, List.of("Bearer sdfsdfsd.sdfsdfsd.sdfsdfsd")));
  }

  @Test
  @DisplayName("Test authenticate method with HttpServletRequest")
  void testAuthenticateWithHttpServletRequest() {
    // Given
    given(userBearerTokenResolver.resolve(httpServletRequest)).willReturn("Bearer token");

    // When
    boolean result = kcAuthProvider.authenticate(httpServletRequest);

    // Then
    assertThat(result).isTrue();
  }

  @Test
  @DisplayName("Test authenticate method with null HttpServletRequest")
  void testAuthenticateWithNullHttpServletRequest() {
    // Given / When
    boolean result = kcAuthProvider.authenticate(null);

    // Then
    assertThat(result).isFalse();
  }

  @Test
  @DisplayName("Test getUserId method")
  void testGetUserId() {
    // Given
    MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();

    // When
    UUID result = kcAuthProvider.getUserId(headers);

    // Then
    assertThat(result).isNotNull();
  }
}
