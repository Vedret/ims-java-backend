package ims_java_backend.ims.security.sso;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpHeaders;

import java.util.HashMap;
import java.util.Map;

@Service
public class TokenIntrospectionService {

    @Value("${security.oauth2.client.clinetId}")
    private String clientId;

    @Value("${security.oauth2.client.clinetSecret}")
    private String clientSecret;

    @Value("${security.oauth2.client.tokenInfoUri}")
    private String tokenInfoUri;



    private final RestTemplate restTemplate;

    @Autowired
    public TokenIntrospectionService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public Map<String, ?> introspectToken (String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Content-Type", "application/x-www-form-urlencoded");
        headers.setBasicAuth(clientId, clientSecret); // Basic Auth credentials if required

        // Create the body for the POST request
        Map<String, String> body = new HashMap<>();
        body.put("token", accessToken);

        HttpEntity<Map<String, String>> requestEntity = new HttpEntity<> (body, headers);

        // Perform the POST request to introspect the token

        ResponseEntity<Map> responseEntity = restTemplate.exchange(
                tokenInfoUri,
                HttpMethod.POST,
                requestEntity,
                Map.class
        );

        return responseEntity.getBody();

    }
}
