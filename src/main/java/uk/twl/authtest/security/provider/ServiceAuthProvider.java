package uk.twl.authtest.security.provider;

import static java.util.Objects.isNull;
import static org.springframework.util.ObjectUtils.isEmpty;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import java.util.Date;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 This class provides functionality for generating and validating JWT tokens to authenticate services.
 */
@Component
@Slf4j
@RequiredArgsConstructor
public class ServiceAuthProvider {
  /** The name of the claim for the authentication provider */
  public static final String AUTH_PROVIDER = "authProvider";

  /** The name of the claim for the user's acceptance of terms */
  public static final String TERMS_ACCEPTED = "termsAccepted";

  /** The name of the claim for the user's ID */
  public static final String USER_ID = "userId";

  /** The parser for parsing JWT tokens */
  private final JwtParser jwtParser;

  /** The builder for building JWT tokens */
  private final JwtBuilder jwtBuilder;

  /** The expiration time of JWT tokens, in seconds */
  @Value("${jwt.expiration}")
  private final int jwtExpiration;

  /** The name of the service authorization header */
  @Value("${jwt.serviceAuthorisationHeaderName}")
  private final String serviceAuthorisationHeaderName;

  /**
   Generates a JWT token for the given user ID, terms acceptance, and authentication provider.

   @param userId the ID of the user
   @param termsAccepted whether the user has accepted the terms
   @param authProviderMap the authentication provider
   @return the generated JWT token
   */
  public String generateToken(UUID userId, boolean termsAccepted, MpAuthProviderMap authProviderMap) {
    Date now = new Date();
    Date expiryDate = new Date(now.getTime() + jwtExpiration);

    return jwtBuilder
        .setId(UUID.randomUUID().toString())
        .setIssuedAt(now)
        .setExpiration(expiryDate)
        .claim(USER_ID, userId)
        .claim(TERMS_ACCEPTED, termsAccepted)
        .claim(AUTH_PROVIDER, authProviderMap)
        .compact();
  }

  /**

   Generates a Bearer token for the given user ID, terms acceptance, and authentication provider.

   @param userId the ID of the user
   @param termsAccepted whether the user has accepted the terms
   @param authProviderMap the authentication provider
   @return the generated Bearer token
   */
  public String generateBearerToken(UUID userId, boolean termsAccepted, MpAuthProviderMap authProviderMap) {
    return "Bearer " + generateToken(userId, termsAccepted, authProviderMap);
  }

  /**
   Validates the given JWT token.

   @param token the JWT token to validate
   @return whether the JWT token is valid
   */
  public boolean validateToken(String token) {
    try {
      Jws<Claims> claims = getClaimsJws(token);
      String id = claims.getBody().getId();
      String userId = claims.getBody().get(USER_ID, String.class);
      String authProviderMapName = claims.getBody().get(AUTH_PROVIDER, String.class);
      MpAuthProviderMap authProviderMap = MpAuthProviderMap.getAuthProviderMap(authProviderMapName);
      if (isEmpty(id) || isEmpty(userId) || isNull(authProviderMap)) {
        log.error("Blank or Invalid claims in JWT token");
        return false;
      }
      if (!authProviderMap.isEnabled()) {
        log.error("authProvider {} is not enabled", authProviderMap);
        return false;
      }

      return true;
    } catch (MalformedJwtException ex) {
      log.error("Invalid JWT token");
    } catch (ExpiredJwtException ex) {
      log.error("Expired JWT token");
    } catch (UnsupportedJwtException ex) {
      log.error("Unsupported JWT token");
    } catch (IllegalArgumentException ex) {
      log.error("JWT claims string is empty");
    }
    return false;
  }

  /**
   Parses the given JWT token and returns the claims.

   @param token the JWT token to parse
   @return the claims of the JWT token
   */
  public Jws<Claims> getClaimsJws(String token) {
    return jwtParser.parseClaimsJws(token);
  }

  /**
   Returns the name of the service authorization header.

   @return the name of the service authorization header
   */
  public String getHeaderName() {
    return serviceAuthorisationHeaderName;
  }
}
