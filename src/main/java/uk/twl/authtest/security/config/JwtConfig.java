package uk.twl.authentication.config;

import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import java.security.Key;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class JwtConfig {

    @Value("${jwt.secret}")
    private final String jwtSecret;

    @Bean
    protected Key jwtKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    @Bean
    protected JwtParser jwtParser(Key jwtKey) {
        return Jwts.parserBuilder().setSigningKey(jwtKey).build();
    }
}
