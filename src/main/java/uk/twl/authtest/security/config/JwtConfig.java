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
 This class provides configuration for JSON Web Tokens (JWTs) used in the application's security.
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
   Returns the JWT secret key.
   
   @return the JWT secret key
   */
  @Bean
  public Key jwtKey() {
    return Keys.hmacShaKeyFor(jwtSecret.getBytes());
  }

  /**
   Returns the JWT builder.

   @param jwtKey the JWT secret key
   @return the JWT builder
   */
  @Bean
  public JwtBuilder jwtBuilder(Key jwtKey) {
    return Jwts.builder()
        .signWith(jwtKey, signatureAlgorithm)
        .serializeToJsonWith(new JacksonSerializer<>(objectMapper));
  }

  /**
   Returns the JWT parser.

   @param jwtKey the JWT secret key
   @return the JWT parser
   */
  @Bean
  public JwtParser jwtParser(Key jwtKey) {
    return Jwts.parserBuilder()
        .setSigningKey(jwtKey)
        .deserializeJsonWith(new JacksonDeserializer<>(objectMapper))
        .build();
  }

  /**
   Returns the service bearer token resolver.

   @return the service bearer token resolver
   */
  @Bean("serviceBearerTokenResolver")
  public DefaultBearerTokenResolver serviceBearerTokenResolver() {
    DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
    resolver.setBearerTokenHeaderName(serviceAuthorisationHeaderName);
    return resolver;
  }

  /**
   Returns the user bearer token resolver.

   @return the user bearer token resolver
   */
  @Bean("userBearerTokenResolver")
  public DefaultBearerTokenResolver userBearerTokenResolver() {
    DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
    resolver.setBearerTokenHeaderName(userAuthorisationHeaderName);
    return resolver;
  }
}
