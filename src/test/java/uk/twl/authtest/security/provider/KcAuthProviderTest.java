package uk.twl.authtest.security.provider;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;

import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import org.assertj.core.util.Lists;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

@ExtendWith(MockitoExtension.class)
@DisplayName("KcAuthProvider Unit Tests")
public class KcAuthProviderTest {

    @Mock
    private BearerTokenResolver userBearerTokenResolver;

    @InjectMocks
    private KcAuthProvider kcAuthProvider;

    @Value("${jwt.userAuthorisationHeaderName}")
    private String userAuthorisationHeaderName;

    @Test
    @DisplayName("Test authenticate method with valid username and password")
    void testAuthenticateWithValidUsernameAndPassword() {
        String username = "test";
        String password = "test123";
        MultiValueMap<String, String> expectedResult = new LinkedMultiValueMap<>();
        expectedResult.add(userAuthorisationHeaderName, Lists.list("Bearer sdfsdfsd.sdfsdfsd.sdfsdfsd"));

        MultiValueMap<String, String> result = kcAuthProvider.authenticate(username, password);

        assertThat(result).isEqualTo(expectedResult);
    }

    @Test
    @DisplayName("Test authenticate method with invalid username and password")
    void testAuthenticateWithInvalidUsernameAndPassword() {
        String username = "invalid";
        String password = "invalid123";
        MultiValueMap<String, String> expectedResult = new LinkedMultiValueMap<>();

        MultiValueMap<String, String> result = kcAuthProvider.authenticate(username, password);

        assertThat(result).isEqualTo(expectedResult);
    }

    @Test
    @DisplayName("Test authenticate method with null username and password")
    void testAuthenticateWithNullUsernameAndPassword() {
        MultiValueMap<String, String> expectedResult = new LinkedMultiValueMap<>();

        MultiValueMap<String, String> result = kcAuthProvider.authenticate(null, null);

        assertThat(result).isEqualTo(expectedResult);
    }

    @Test
    @DisplayName("Test authenticate method with null username")
    void testAuthenticateWithNullUsername() {
        String password = "test123";
        MultiValueMap<String, String> expectedResult = new LinkedMultiValueMap<>();

        MultiValueMap<String, String> result = kcAuthProvider.authenticate(null, password);

        assertThat(result).isEqualTo(expectedResult);
    }

    @Test
    @DisplayName("Test authenticate method with null password")
    void testAuthenticateWithNullPassword() {
        String username = "test";
        MultiValueMap<String, String> expectedResult = new LinkedMultiValueMap<>();

        MultiValueMap<String, String> result = kcAuthProvider.authenticate(username, null);

        assertThat(result).isEqualTo(expectedResult);
    }

    @Test
    @DisplayName("Test authenticate method with null HttpServletRequest")
    void testAuthenticateWithNullHttpServletRequest() {
        boolean result = kcAuthProvider.authenticate(null);
        assertThat(result).isFalse();
    }

    @Test
    @DisplayName("Test authenticate method with HttpServletRequest")
    void testAuthenticateWithHttpServletRequest() {
        HttpServletRequest httpServletRequest = mock(HttpServletRequest.class);
        given(userBearerTokenResolver.resolve(httpServletRequest)).willReturn("Bearer token");

        boolean result = kcAuthProvider.authenticate(httpServletRequest);

        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("Test getUserId method")
    void testGetUserId() {
        MultiValueMap<String, String> headers = new LinkedMultiValueMap<>();
        UUID expectedUserId = UUID.randomUUID();
        given(kcAuthProvider.getUserId(eq(headers))).willReturn(expectedUserId);

        UUID result = kcAuthProvider.getUserId(headers);

        assertThat(result).isEqualTo(expectedUserId);
    }
}
