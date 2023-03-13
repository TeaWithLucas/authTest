package uk.twl.authtest.security.filter;


import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static uk.twl.authtest.security.provider.ServiceAuthProvider.AUTH_PROVIDER;
import static uk.twl.authtest.security.provider.ServiceAuthProvider.USER_ID;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.web.filter.OncePerRequestFilter;
import uk.twl.authtest.security.provider.AuthProvider;
import uk.twl.authtest.security.provider.MpAuthProviderMap;
import uk.twl.authtest.security.provider.ServiceAuthProvider;
import uk.twl.authtest.security.service.MpAuthProviderMapService;

/**
 This class implements a filter that handles authentication requests for services using JWT tokens.
 */
@RequiredArgsConstructor
public class AuthenticationRequestFilter extends OncePerRequestFilter {
  private final ServiceAuthProvider serviceAuthProvider;

  /** The resolver for resolving Bearer tokens */
  public final BearerTokenResolver serviceBearerTokenResolver;

  /** The service for getting authentication provider maps */
  private final MpAuthProviderMapService authProviderMapService;

  /**

   Filters the incoming HTTP request.
   @param request the incoming HTTP request
   @param response the HTTP response to send
   @param chain the filter chain to use
   @throws ServletException if the request cannot be handled
   @throws IOException if an I/O error occurs
   */
  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {

    final String serviceAuthorisationToken = serviceBearerTokenResolver.resolve(request);

    if (!serviceAuthProvider.validateToken(serviceAuthorisationToken)) {
      logger.error("JWT Token is not valid");
      response.setStatus(UNAUTHORIZED.value());
      return;
    }

    Jws<Claims> claimsJws = serviceAuthProvider.getClaimsJws(serviceAuthorisationToken);

    String authProviderMapString = claimsJws.getBody().get(AUTH_PROVIDER, String.class);
    MpAuthProviderMap authProviderMap = MpAuthProviderMap.getAuthProviderMap(authProviderMapString);

    AuthProvider authProvider = authProviderMapService.getAuthProvider(authProviderMap);

    Instant issuedAt = claimsJws.getBody().getIssuedAt().toInstant();
    Instant expiresAt = claimsJws.getBody().getExpiration().toInstant();

    if (!authProvider.authenticate(request)) {
      logger.error("authProvider failed to authenticate");
      response.setStatus(UNAUTHORIZED.value());
      return;
    }

    Jwt jwt = new Jwt(serviceAuthorisationToken, issuedAt,
        expiresAt, claimsJws.getHeader(), claimsJws.getBody());

    JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of());

    SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);

    UUID userId = UUID.fromString(claimsJws.getBody().get(USER_ID, String.class));
    String serviceHeaderValue = serviceAuthProvider.generateBearerToken(userId, false, authProviderMap);
    String serviceHeaderName = serviceAuthProvider.getHeaderName();

    response.setHeader(serviceHeaderName, serviceHeaderValue);

    chain.doFilter(request, response);
  }
}
