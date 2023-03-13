package uk.twl.authtest.security.config;

import java.util.ArrayList;
import java.util.List;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/**

 This class holds the security properties for the application.
 */
@Configuration
@EnableWebSecurity
@ConfigurationProperties(prefix = "security")
@Data
public class SecurityProperties {
  /** The list of anonymous paths */
  private final List<String> anonymousPaths = new ArrayList<>();

  /**
   Returns the array of anonymous paths.
   
   @return the array of anonymous paths
   */
  public String[] getAnonymousPathsArray() {
    return anonymousPaths.toArray(String[]::new);
  }
}
