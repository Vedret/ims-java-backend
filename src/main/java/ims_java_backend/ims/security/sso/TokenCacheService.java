package ims_java_backend.ims.security.sso;

import ims_java_backend.ims.exceptions.TokenValidationException;
import lombok.RequiredArgsConstructor;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Objects;
import java.util.Map;


@Component
@RequiredArgsConstructor
public class TokenCacheService {

    private final CacheManager cacheManager;

    private final  TokenIntrospectionService tokenIntrospectionService;

    public void validateToken(String accessToken) {
        Objects.requireNonNull(accessToken, "Access token must not be null");

        // Introspect the token
        Map<String, ?> introspection = tokenIntrospectionService.introspectToken(accessToken);

        if (introspection != null) {
            // Check if the token is active
            Boolean isActive = (Boolean) introspection.get("active");
            Long expiresAt = (Long) introspection.get("exp"); // Get the expiration timestamp

            // Check if the token is not active
            if (Boolean.FALSE.equals(isActive)) {
                evictToken(accessToken);
                throw new TokenValidationException("Token is not active.");
            }

            // Check if the token has expired
            if (expiresAt != null && Instant.now().getEpochSecond() > expiresAt) {
                evictToken(accessToken);
                throw new TokenValidationException("Token has expired.");
            }
        } else {
            throw new TokenValidationException("Introspection response is null or invalid.");
        }
    }

    private void evictToken(String accessToken) {
        Cache cache = cacheManager.getCache("tokenCache");
        if (cache != null) {
            cache.evict(accessToken);
        }
    }

    public Map<String, ?> putIfAbsent(String accessToken, Map<String, ?> tokenData) {
        Objects.requireNonNull(accessToken, "Access token must not be null");
        Objects.requireNonNull(tokenData, "Token data must not be null");

        // Validate the token before putting it in the cache
        validateToken(accessToken);

        Cache cache = cacheManager.getCache("tokenCache");
        Cache.ValueWrapper existingValue = cache.get(accessToken);

        // Check if the token is absent in the cache
        if (existingValue == null) {
            // Put the token data into the cache and return the token data
            cache.put(accessToken, tokenData);
            return tokenData; // Return the newly cached token data
        }

        return (Map<String, ?>) existingValue.get();
    }

    public boolean evictIfExpired(String accessToken) {
        Objects.requireNonNull(accessToken, "Access token must not be null");

        try {
            // Validate the token to evict if necessary
            validateToken(accessToken);
            return false; // Token is valid, not evicted
        } catch (TokenValidationException e) {
            // If token is not valid, evict it and return true
            evictToken(accessToken);
            return true;
        }
    }
}
