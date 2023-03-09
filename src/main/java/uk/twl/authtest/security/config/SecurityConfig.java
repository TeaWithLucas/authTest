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

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final SecurityProperties securityProperties;

    private final ServiceAuthProvider serviceAuthProvider;
    @Qualifier("serviceBearerTokenResolver")
    public final BearerTokenResolver serviceBearerTokenResolver;

    private final MpAuthProviderMapService authProviderMapService;

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

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.ignoring().antMatchers(securityProperties.getAnonymousPathsArray());
    }

    private AuthenticationRequestFilter getAuthenticationRequestFilter() {
        return new AuthenticationRequestFilter(serviceAuthProvider, serviceBearerTokenResolver, authProviderMapService);
    }
}
