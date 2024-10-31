package ims_java_backend.ims.security.sso;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.client.RestTemplate;

public class OktaAuthenticationProvider implements AuthenticationProvider {

    private final RestTemplate restTemplate;

    private  TokenCacheService tokenCache;

    public OktaAuthenticationProvider(TokenCacheService tokenCacheService) {
        restTemplate = new RestTemplate();
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return false;
    }
}
