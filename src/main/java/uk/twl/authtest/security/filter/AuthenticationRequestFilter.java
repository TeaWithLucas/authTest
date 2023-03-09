package uk.twl.authtest.security.filter;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import uk.twl.authtest.security.provider.MpTokenProvider;
import uk.twl.authtest.security.provider.MpAuthProvider;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;
import static org.springframework.util.ObjectUtils.isEmpty;

@Component
@RequiredArgsConstructor
public class JwtRequestFilter extends OncePerRequestFilter {
    private final MpTokenProvider mpTokenProvider;
    @Qualifier("serviceBearerTokenResolver")
    public final BearerTokenResolver serviceBearerTokenResolver;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
        throws ServletException, IOException {

        final String serviceAuthorisationToken = serviceBearerTokenResolver.resolve(request);

        if (!mpTokenProvider.validateToken(serviceAuthorisationToken)) {
            logger.error("JWT Token is not valid");
            response.setStatus(UNAUTHORIZED.value());
            return;
        }

        Jws<Claims> claimsJws = mpTokenProvider.getClaimsJws(serviceAuthorisationToken);

        MpAuthProvider authProvider = claimsJws.getBody().get("AuthProvider", MpAuthProvider.class);
        Instant issuedAt = claimsJws.getBody().getIssuedAt().toInstant();
        Instant expiresAt = claimsJws.getBody().getExpiration().toInstant();

        if(!authProvider.authenticate(request)) {
            logger.error("authProvider failed to authenticate");
            response.setStatus(UNAUTHORIZED.value());
            return;
        }

        Jwt jwt = new Jwt(serviceAuthorisationToken, issuedAt,
            expiresAt, claimsJws.getHeader(), claimsJws.getBody());

        JwtAuthenticationToken jwtAuthenticationToken = new JwtAuthenticationToken(jwt, List.of());

        SecurityContextHolder.getContext().setAuthentication(jwtAuthenticationToken);


        response.setHeader();

        chain.doFilter(request, response);
    }
}
