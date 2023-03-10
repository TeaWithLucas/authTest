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

@Component
@Slf4j
@RequiredArgsConstructor
public class ServiceAuthProvider {
    public static final String AUTH_PROVIDER = "authProvider";
    public static final String TERMS_ACCEPTED = "termsAccepted";
    public static final String USER_ID = "userId";
    private final JwtParser jwtParser;
    private final JwtBuilder jwtBuilder;

    @Value("${jwt.expiration}")
    private final int jwtExpiration;

    @Value("${jwt.serviceAuthorisationHeaderName}")
    private final String serviceAuthorisationHeaderName;

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

    public String generateBearerToken(UUID userId, boolean termsAccepted, MpAuthProviderMap authProviderMap) {
        return "Bearer " + generateToken(userId, termsAccepted, authProviderMap);
    }

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

    public Jws<Claims> getClaimsJws(String token) {
        return jwtParser.parseClaimsJws(token);
    }

    public String getHeaderName() {
        return serviceAuthorisationHeaderName;
    }
}
