package uk.twl.authtest.security.provider;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.List;
import java.util.Map;
import java.util.UUID;
import javax.servlet.http.HttpServletRequest;

import static org.springframework.util.ObjectUtils.isEmpty;

@Component
@RequiredArgsConstructor
@Slf4j
public class KcAuthProvider implements MpAuthProvider {

    @Value("${jwt.userAuthorisationHeaderName}")
    private final String userAuthorisationHeaderName;

    @Qualifier("userBearerTokenResolver")
    public final BearerTokenResolver userBearerTokenResolver;

    @Override
    public String getName() {
        return KcAuthProvider.class.getSimpleName();
    }

    @Override
    public MultiValueMap<String, String> authenticate(String username, String password) {
        // TODO get token from KcManagerApi
        String token = "sdfsdfsd.sdfsdfsd.sdfsdfsd";
        return new LinkedMultiValueMap<>(Map.of(
            userAuthorisationHeaderName,
            List.of("Bearer " + token))
        );
    }

    @Override
    public boolean authenticate(HttpServletRequest request) {

        final String userAuthorisationToken = userBearerTokenResolver.resolve(request);


        if (isEmpty(userAuthorisationToken)) {
            log.info("User token is {}", userAuthorisationToken);
            return false;
        }

        // TODO: call KcManagerApi to validate the token

        return true;
    }

    @Override
    public UUID getUserId(MultiValueMap<String, String> headers) {
        // TODO get userId from KcManagerApi
        return UUID.randomUUID();
    }

}
