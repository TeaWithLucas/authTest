package uk.twl.authtest.security.controller.request;

import lombok.Data;
import uk.twl.authtest.security.provider.MpAuthProvider;

@Data
public class JwtRequest {
    private final String username;
    private final String password;

    private final MpAuthProvider mpAuthProvider;
}
