package uk.twl.authtest.security.provider;

import org.springframework.util.MultiValueMap;

import java.util.UUID;
import javax.servlet.http.HttpServletRequest;

public interface AuthProvider {

    String getName();
    MultiValueMap<String, String> authenticate(String username, String password);
    boolean authenticate(HttpServletRequest request);

    UUID getUserId(MultiValueMap<String, String> headers);
}
