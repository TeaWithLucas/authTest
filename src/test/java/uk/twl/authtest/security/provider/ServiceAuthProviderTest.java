package uk.twl.authtest.security.provider;import static org.assertj.core.api.Assertions.assertThat;import static org.mockito.ArgumentMatchers.any;import static org.mockito.ArgumentMatchers.anyString;import static org.mockito.ArgumentMatchers.eq;import static org.mockito.BDDMockito.given;import static org.mockito.Mockito.times;import static org.mockito.Mockito.verify;import static uk.twl.authtest.security.provider.MpAuthProviderMap.KC_AUTH_PROVIDER;import static uk.twl.authtest.security.provider.ServiceAuthProvider.AUTH_PROVIDER;import static uk.twl.authtest.security.provider.ServiceAuthProvider.TERMS_ACCEPTED;import static uk.twl.authtest.security.provider.ServiceAuthProvider.USER_ID;import io.jsonwebtoken.Claims;import io.jsonwebtoken.ExpiredJwtException;import io.jsonwebtoken.Jws;import io.jsonwebtoken.JwtBuilder;import io.jsonwebtoken.JwtException;import io.jsonwebtoken.JwtParser;import io.jsonwebtoken.Jwts;import io.jsonwebtoken.MalformedJwtException;import io.jsonwebtoken.UnsupportedJwtException;import io.jsonwebtoken.jackson.io.JacksonDeserializer;import io.jsonwebtoken.jackson.io.JacksonSerializer;import java.security.Key;import java.util.Date;import java.util.UUID;import org.junit.jupiter.api.BeforeEach;import org.junit.jupiter.api.DisplayName;import org.junit.jupiter.api.Test;import org.junit.jupiter.api.extension.ExtendWith;import org.junit.jupiter.params.ParameterizedTest;import org.junit.jupiter.params.provider.EmptySource;import org.junit.jupiter.params.provider.NullAndEmptySource;import org.junit.jupiter.params.provider.ValueSource;import org.mockito.InjectMocks;import org.mockito.Mock;import org.mockito.junit.jupiter.MockitoExtension;import org.springframework.context.annotation.Bean;@DisplayName("ServiceAuthProvider Unit Tests")@ExtendWith(MockitoExtension.class)class ServiceAuthProviderTest {  public static final int EXPIRATION = 1234;  public static final String HEADER_NAME = "HeaderName";  @Mock  private JwtBuilder jwtBuilder;  @Mock  private JwtParser jwtParser;  private ServiceAuthProvider serviceAuthProvider;  @Mock  private Jws<Claims> claimsJws;  @Mock  private Claims body;  @Mock  private MpAuthProviderMap mpAuthProviderMap;  @BeforeEach  void setup() {    serviceAuthProvider = new ServiceAuthProvider(jwtParser, jwtBuilder, EXPIRATION, HEADER_NAME);  }  @Test  @DisplayName("generateToken method generates a JWT token with valid parameters")  void testGenerateTokenWithValidParameters() {    // Given    given(jwtBuilder.setId(anyString())).willReturn(jwtBuilder);    given(jwtBuilder.setIssuedAt(any(Date.class))).willReturn(jwtBuilder);    given(jwtBuilder.setExpiration(any(Date.class))).willReturn(jwtBuilder);    given(jwtBuilder.claim(anyString(), any())).willReturn(jwtBuilder);    given(jwtBuilder.compact()).willReturn("jwtString");    UUID userId = UUID.randomUUID();    // When    String token = serviceAuthProvider.generateToken(userId, true, KC_AUTH_PROVIDER);    // Then    assertThat(token).isEqualTo("jwtString");    verify(jwtBuilder, times(1)).setId(anyString());    verify(jwtBuilder, times(1)).setIssuedAt(any(Date.class));    verify(jwtBuilder, times(1)).setExpiration(any(Date.class));    verify(jwtBuilder, times(1)).claim(USER_ID, userId);    verify(jwtBuilder, times(1)).claim(TERMS_ACCEPTED, true);    verify(jwtBuilder, times(1)).claim(AUTH_PROVIDER, KC_AUTH_PROVIDER);  }  @Test  @DisplayName("generateBearerToken method should generate a valid bearer token")  void testGenerateBearerToken() {    // Given    given(jwtBuilder.setId(anyString())).willReturn(jwtBuilder);    given(jwtBuilder.setIssuedAt(any(Date.class))).willReturn(jwtBuilder);    given(jwtBuilder.setExpiration(any(Date.class))).willReturn(jwtBuilder);    given(jwtBuilder.claim(anyString(), any())).willReturn(jwtBuilder);    given(jwtBuilder.compact()).willReturn("jwtString");    // When    String token = serviceAuthProvider.        generateBearerToken(UUID.randomUUID(), true, KC_AUTH_PROVIDER);    // Then    assertThat(token).isEqualTo("Bearer jwtString");  }  @Test  @DisplayName("Given a valid token, when calling the validateToken method of ServiceAuthProvider, "      + "then it should return true.")  void testValidateTokenWithValidToken() {    // Given    String testToken = "testToken";    given(jwtParser.parseClaimsJws(testToken)).willReturn(claimsJws);    given(claimsJws.getBody()).willReturn(body);    given(body.getId()).willReturn("id");    given(body.get(USER_ID, String.class)).willReturn("id");    given(body.get(AUTH_PROVIDER, String.class)).willReturn("KC_AUTH_PROVIDER");    // When    boolean result = serviceAuthProvider.validateToken(testToken);    // Then    assertThat(result).isTrue();  }  @ParameterizedTest(name = "Given exception of {0}")  @ValueSource(classes = {      MalformedJwtException.class,      ExpiredJwtException.class,      IllegalArgumentException.class,      UnsupportedJwtException.class  })  @DisplayName("Given an invalid token of type then validateToken it should return false")  void testValidateTokenWithInvalidToken(Class<JwtException> value) {    // Given    String testToken = "testToken";    given(jwtParser.parseClaimsJws(testToken)).willThrow(value);    // When    boolean result = serviceAuthProvider.validateToken(testToken);    // Then    assertThat(result).isFalse();  }  @ParameterizedTest  @NullAndEmptySource  @DisplayName("Given a blank ID, when validating a token, then the method should return false")  void testValidateTokenWithBlankId(String value) {    // Given    String testToken = "testToken";    given(jwtParser.parseClaimsJws(testToken)).willReturn(claimsJws);    given(claimsJws.getBody()).willReturn(body);    given(body.getId()).willReturn(value);    given(body.get(USER_ID, String.class)).willReturn("id");    given(body.get(AUTH_PROVIDER, String.class)).willReturn("KC_AUTH_PROVIDER");    // When    boolean result = serviceAuthProvider.validateToken(testToken);    // Then    assertThat(result).isFalse();  }  @ParameterizedTest  @NullAndEmptySource  @DisplayName("Given a blank USER_ID claim, when validating a token, "      + "then the method should return false")  void testValidateTokenWithBlankUserIdClaim(String value) {    // Given    String testToken = "testToken";    given(jwtParser.parseClaimsJws(testToken)).willReturn(claimsJws);    given(claimsJws.getBody()).willReturn(body);    given(body.getId()).willReturn("id");    given(body.get(USER_ID, String.class)).willReturn(value);    given(body.get(AUTH_PROVIDER, String.class)).willReturn("KC_AUTH_PROVIDER");    // When    boolean result = serviceAuthProvider.validateToken(testToken);    // Then    assertThat(result).isFalse();  }  @ParameterizedTest  @NullAndEmptySource  @DisplayName("Given a blank AUTH_PROVIDER claim, when validating a token, "      + "then the method should return false")  void testValidateTokenWithBlankAuthProviderClaim(String value) {    // Given    String testToken = "testToken";    given(jwtParser.parseClaimsJws(testToken)).willReturn(claimsJws);    given(claimsJws.getBody()).willReturn(body);    given(body.getId()).willReturn("id");    given(body.get(USER_ID, String.class)).willReturn("id");    given(body.get(AUTH_PROVIDER, String.class)).willReturn(value);    // When    boolean result = serviceAuthProvider.validateToken(testToken);    // Then    assertThat(result).isFalse();  }  @Test  @DisplayName("Given a disabled AUTH_PROVIDER claim, when validating a token, "      + "then the method should return false")  void testValidateTokenWithDisabledAuthProvider() {    // Given    String testToken = "testToken";    given(jwtParser.parseClaimsJws(testToken)).willReturn(claimsJws);    given(claimsJws.getBody()).willReturn(body);    given(body.getId()).willReturn("id");    given(body.get(USER_ID, String.class)).willReturn("id");    given(body.get(AUTH_PROVIDER, String.class)).willReturn("NIM_AUTH_PROVIDER");    // When    boolean result = serviceAuthProvider.validateToken(testToken);    // Then    assertThat(result).isFalse();  }  @Test  @DisplayName("The getHeaderName method should return the correct header name")  void testGetHeaderNameWithValidHeaderName() {    // Given / When    String result = serviceAuthProvider.getHeaderName();    // Then    assertThat(result).isEqualToIgnoringCase(HEADER_NAME);  }}