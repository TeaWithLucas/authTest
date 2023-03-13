package uk.twl.authtest.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.jackson.io.JacksonDeserializer;
import io.jsonwebtoken.jackson.io.JacksonSerializer;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

/**

 Configuration class for JWT (JSON Web Token) related beans and settings. This class provides beans for creating,
 parsing and validating JWT tokens. It also provides beans for configuring bearer token resolvers for service and user
 authorizations.
 */
@Configuration
@RequiredArgsConstructor
public class JwtConfig {

  /** The JWT secret */
  @Value("${jwt.secret}")
  private final String jwtSecret;

  /** The JWT signature algorithm */
  @Value("${jwt.signatureAlgorithm}")
  private SignatureAlgorithm signatureAlgorithm;

  /** The service authorisation header name */
  @Value("${jwt.serviceAuthorisationHeaderName}")
  private final String serviceAuthorisationHeaderName;

  /** The user authorisation header name */
  @Value("${jwt.userAuthorisationHeaderName}")
  private final String userAuthorisationHeaderName;

  /** The object mapper */
  private final ObjectMapper objectMapper = new ObjectMapper();

  /**
   Creates a HMAC SHA key based on the JWT secret.

   @return the HMAC SHA key used for signing and verifying JWT tokens.
   */
  @Bean
  public Key jwtKey() {
    return Keys.hmacShaKeyFor(jwtSecret.getBytes());
  }

  /**
   Creates a JWT builder with the specified key and signature algorithm.

   @param jwtKey the key used for signing JWT tokens.
   @return the JWT builder instance.
   */
  @Bean
  public JwtBuilder jwtBuilder(Key jwtKey) {
    return Jwts.builder()
        .signWith(jwtKey, signatureAlgorithm)
        .serializeToJsonWith(new JacksonSerializer<>(objectMapper));
  }

  /**
   Creates a JWT parser with the specified key and object mapper.

   @param jwtKey the key used for verifying JWT tokens.
   @return the JWT parser instance.
   */
  @Bean
  public JwtParser jwtParser(Key jwtKey) {
    return Jwts.parserBuilder()
        .setSigningKey(jwtKey)
        .deserializeJsonWith(new JacksonDeserializer<>(objectMapper))
        .build();
  }

  /**
   Creates a bearer token resolver for service authorizations using the configured header name.

   @return the bearer token resolver instance for service authorizations.
   */
  @Bean("serviceBearerTokenResolver")
  public DefaultBearerTokenResolver serviceBearerTokenResolver() {
    DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
    resolver.setBearerTokenHeaderName(serviceAuthorisationHeaderName);
    return resolver;
  }

  /**
   Creates a bearer token resolver for user authorizations using the configured header name.

   @return the bearer token resolver instance for user authorizations.
   */
  @Bean("userBearerTokenResolver")
  public DefaultBearerTokenResolver userBearerTokenResolver() {
    DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
    resolver.setBearerTokenHeaderName(userAuthorisationHeaderName);
    return resolver;
  }
}
