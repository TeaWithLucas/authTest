package uk.twl.authtest.security.provider;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

@ExtendWith(MockitoExtension.class)
@DisplayName("Kc Auth Provider Unit Tests")
class NimAuthProviderTest {

  public static final String USERNAME = "test";
  public static final String PASSWORD = "test123";
  @InjectMocks
  private NimAuthProvider nimAuthProvider;

  @Mock
  private HttpServletRequest httpServletRequest;


  @Test
  @DisplayName("Test authenticate method with valid username and password")
  void testAuthenticateWithValidUsernameAndPassword() {
    // Given / When
    MultiValueMap<String, String> result = nimAuthProvider.authenticate(USERNAME, PASSWORD);

    // Then
    assertThat(result).isEmpty();
  }


  @Test
  @DisplayName("Test authenticate method with null username and password")
  void testAuthenticateWithNullUsernameAndPassword() {
    // Given / When
    MultiValueMap<String, String> result = nimAuthProvider.authenticate(null, null);

    // Then
    assertThat(result).isEmpty();
  }

  @Test
  @DisplayName("Test authenticate method with HttpServletRequest")
  void testAuthenticateWithHttpServletRequest() {
    // Given / When
    boolean result = nimAuthProvider.authenticate(httpServletRequest);

    // Then
    assertThat(result).isTrue();
  }

  @Test
  @DisplayName("Test authenticate method with null HttpServletRequest")
  void testAuthenticateWithNullHttpServletRequest() {
    // Given / When
    boolean result = nimAuthProvider.authenticate(null);

    // Then
    assertThat(result).isTrue();
  }

  @Test
  @DisplayName("Test getUserId method")
  void testGetUserId() {
    // Given
    MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();

    // When
    UUID result = nimAuthProvider.getUserId(headers);

    // Then
    assertThat(result).isNull();
  }
}
