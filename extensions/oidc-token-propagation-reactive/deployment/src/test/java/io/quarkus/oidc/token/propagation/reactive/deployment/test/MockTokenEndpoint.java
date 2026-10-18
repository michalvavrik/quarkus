package io.quarkus.oidc.token.propagation.reactive.deployment.test;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.FormParam;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import io.quarkus.test.oidc.server.OidcWiremockTestResource;
import io.vertx.core.json.JsonObject;

/**
 * Token endpoint which exchanges the subject token or the JWT bearer assertion for a token issued to 'bob',
 * unless a different response is configured for the exchanged token.
 */
@Path("/mock-oidc/token")
public class MockTokenEndpoint {

    private record TokenResponse(int status, String body) {
    }

    private static final Map<String, TokenResponse> responses = new ConcurrentHashMap<>();
    private static final Map<String, AtomicInteger> exchanges = new ConcurrentHashMap<>();

    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.APPLICATION_JSON)
    public Response exchange(@FormParam("subject_token") String subjectToken, @FormParam("assertion") String assertion) {
        String tokenToExchange = subjectToken != null ? subjectToken : assertion;
        exchanges.computeIfAbsent(tokenToExchange, t -> new AtomicInteger()).incrementAndGet();
        TokenResponse response = responses.getOrDefault(tokenToExchange, tokenIssuedTo("bob"));
        return Response.status(response.status()).entity(response.body()).build();
    }

    static void respondWithTokenIssuedTo(String tokenToExchange, String userName) {
        responses.put(tokenToExchange, tokenIssuedTo(userName));
    }

    static void respondWithTokenIssuedTo(String tokenToExchange, String userName, int expiresInSeconds) {
        responses.put(tokenToExchange,
                new TokenResponse(200, tokenJson(userName).put("expires_in", expiresInSeconds).encode()));
    }

    static void respondWithError(String tokenToExchange) {
        responses.put(tokenToExchange, new TokenResponse(400, "{\"error\":\"invalid_grant\"}"));
    }

    static int exchangeCount(String tokenToExchange) {
        AtomicInteger count = exchanges.get(tokenToExchange);
        return count == null ? 0 : count.get();
    }

    private static TokenResponse tokenIssuedTo(String userName) {
        return new TokenResponse(200, tokenJson(userName).encode());
    }

    private static JsonObject tokenJson(String userName) {
        return new JsonObject().put("access_token", OidcWiremockTestResource.getAccessToken(userName, Set.of("user")));
    }
}
