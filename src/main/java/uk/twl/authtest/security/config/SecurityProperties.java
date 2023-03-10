package uk.twl.authtest.security.config;

import java.util.ArrayList;
import java.util.List;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

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
