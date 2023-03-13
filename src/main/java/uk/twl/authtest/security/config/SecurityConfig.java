package uk.twl.authtest.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationFilter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.SecurityFilterChain;
import uk.twl.authtest.security.filter.AuthenticationRequestFilter;
import uk.twl.authtest.security.provider.ServiceAuthProvider;
import uk.twl.authtest.security.service.MpAuthProviderMapService;

/**
 This class provides the security configuration for the application.
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
  /** The security properties */
  private final SecurityProperties securityProperties;

  /** The authentication provider */
  private final ServiceAuthProvider serviceAuthProvider;

  /** The Bearer token resolver */
  @Qualifier("serviceBearerTokenResolver")
  public final BearerTokenResolver serviceBearerTokenResolver;

  /** The authentication provider map service */
  private final MpAuthProviderMapService authProviderMapService;

  /**

   Configures the security filter chain for the application.
   @param http the HTTP security object
   @return the security filter chain
   @throws Exception if there is an error configuring the security filter chain
   */
  @Bean
  public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
        .addFilterBefore(getAuthenticationRequestFilter(), BearerTokenAuthenticationFilter.class)
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .httpBasic().disable()
        .formLogin().disable()
        .logout().disable()
        .csrf().disable();
    return http.build();
  }

  /**
   Returns the web security customizer for the application.
   
   This method defines the list of endpoints that do not require authentication,
   known as anonymous paths.

   @return the web security customizer
   */
  @Bean
  public WebSecurityCustomizer webSecurityCustomizer() {
    return web -> web.ignoring().antMatchers(securityProperties.getAnonymousPathsArray());
  }

  /**

   Returns the authentication request filter.
   @return the authentication request filter
   */
  private AuthenticationRequestFilter getAuthenticationRequestFilter() {
    return new AuthenticationRequestFilter(serviceAuthProvider, serviceBearerTokenResolver, authProviderMapService);
  }
}
