package uk.twl.authtest.security.provider;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static java.util.Objects.isNull;
import static org.springframework.util.ObjectUtils.isEmpty;

@Component
@Slf4j
@RequiredArgsConstructor
public class MpTokenProvider {

    @Value("${jwt.expiration}")
    private int jwtExpiration;

    @Value("${jwt.signatureAlgorithm}")
    private SignatureAlgorithm signatureAlgorithm;

    @Value("${jwt.serviceAuthorisationHeaderName}")
    private final String serviceAuthorisationHeaderName;


    private final Key key;
    private final JwtParser jwtParser;

    public Map<String, String> generateToken(UUID userId, boolean termsAccepted, MpAuthProvider mpAuthProvider) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration);

        String jwt = Jwts.builder()
            .setId(UUID.randomUUID().toString())
            .setIssuedAt(now)
            .setExpiration(expiryDate)
            .claim("userId", userId)
            .claim("termsAccepted", termsAccepted)
            .claim("authProvider", mpAuthProvider)
            .signWith(key, signatureAlgorithm)
            .compact();

        return Map.of(serviceAuthorisationHeaderName, "Bearer " + jwt);
    }

    public boolean validateToken(String token) {
        try {
            Jws<Claims> claims = getClaimsJws(token);
            String id = claims.getBody().getId();
            String userId = claims.getBody().get("userId", String.class);
            MpAuthProvider mpAuthProvider = claims.getBody().get("authProvider", MpAuthProvider.class);
            return !(isEmpty(id) || isEmpty(userId) || isNull(mpAuthProvider));
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
}
