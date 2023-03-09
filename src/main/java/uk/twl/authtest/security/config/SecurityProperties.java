package uk.twl.authtest.security.config;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import uk.twl.authtest.security.filter.AuthenticationRequestFilter;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
@ConfigurationProperties(prefix = "security")
@Data
public class SecurityProperties {
    private final List<String> anonymousPaths = new ArrayList<>();

    public String[] getAnonymousPathsArray() {
        return anonymousPaths.toArray(String[]::new);
    }
}
