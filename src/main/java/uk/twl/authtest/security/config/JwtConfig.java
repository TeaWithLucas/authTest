package uk.twl.authtest.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.jackson.io.JacksonDeserializer;
import io.jsonwebtoken.jackson.io.JacksonSerializer;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

import java.security.Key;

@Configuration
@RequiredArgsConstructor
public class JwtConfig {

    @Value("${jwt.secret}")
    private final String jwtSecret;
    @Value("${jwt.signatureAlgorithm}")
    private SignatureAlgorithm signatureAlgorithm;
    @Value("${jwt.serviceAuthorisationHeaderName}")
    private final String serviceAuthorisationHeaderName;
    @Value("${jwt.userAuthorisationHeaderName}")
    private final String userAuthorisationHeaderName;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Bean
    public Key jwtKey() {
        return Keys.hmacShaKeyFor(jwtSecret.getBytes());
    }

    @Bean
    public JwtBuilder jwtBuilder(Key jwtKey) {
        return Jwts.builder()
            .signWith(jwtKey, signatureAlgorithm)
            .serializeToJsonWith(new JacksonSerializer<>(objectMapper));
    }

    @Bean
    public JwtParser jwtParser(Key jwtKey) {
        return Jwts.parserBuilder()
            .setSigningKey(jwtKey)
            .deserializeJsonWith(new JacksonDeserializer<>(objectMapper))
            .build();
    }

    @Bean("serviceBearerTokenResolver")
    public DefaultBearerTokenResolver serviceBearerTokenResolver() {
        DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
        resolver.setBearerTokenHeaderName(serviceAuthorisationHeaderName);
        return resolver;
    }

    @Bean("userBearerTokenResolver")
    public DefaultBearerTokenResolver userBearerTokenResolver() {
        DefaultBearerTokenResolver resolver = new DefaultBearerTokenResolver();
        resolver.setBearerTokenHeaderName(userAuthorisationHeaderName);
        return resolver;
    }
}
