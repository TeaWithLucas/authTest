package uk.twl.authtest.security.provider;

import java.util.UUID;
import javax.servlet.http.HttpServletRequest;
import org.springframework.util.MultiValueMap;

/**
 This interface defines the methods that an authentication provider should implement in order to authenticate a user and provide user information.
 */
public interface AuthProvider {

    /**
     * Returns the name of the authentication provider.
     *
     * @return the name of the authentication provider
     */
    String getName();

    /**
     * Authenticates a user based on the provided username and password.
     *
     * @param username the username of the user
     * @param password the password of the user
     * @return a {@link MultiValueMap} containing the user information
     */
    MultiValueMap<String, String> authenticate(String username, String password);

    /**
     * Authenticates a user based on the provided {@link HttpServletRequest}.
     *
     * @param request the {@link HttpServletRequest} object containing the user information
     * @return true if the user is authenticated, false otherwise
     */
    boolean authenticate(HttpServletRequest request);


    /**
     * Returns the user ID based on the provided headers.
     *
     * @param headers a {@link MultiValueMap} containing the headers of the user request
     * @return the user ID as a {@link UUID}
     */
    UUID getUserId(MultiValueMap<String, String> headers);
}
