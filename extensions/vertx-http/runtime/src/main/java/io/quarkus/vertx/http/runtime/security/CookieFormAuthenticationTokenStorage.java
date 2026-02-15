package io.quarkus.vertx.http.runtime.security;

import java.util.Arrays;

import io.quarkus.runtime.util.HashUtil;
import io.quarkus.vertx.http.runtime.FormAuthConfig;
import io.quarkus.vertx.http.security.form.token.FormAuthenticationTokenStorage;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

final class CookieFormAuthenticationTokenStorage implements FormAuthenticationTokenStorage {

    private static final String PERSISTENT_LOGIN_MANAGER_KEY = "io.quarkus.vertx.http.runtime.security#login-manager";
    private final String cookieName;

    CookieFormAuthenticationTokenStorage(FormAuthConfig.FormAuthenticationToken tokenConfig) {
        this.cookieName = tokenConfig.cookieName();
    }

    @Override
    public Uni<Void> storeToken(char[] token, String principalName, RoutingContext routingContext) {
        PersistentLoginManager persistentLoginManager = getPersistentLoginManager(routingContext);

        // FIXME: generate token and save it to the session cookie
        // FIXME: send the token asynchronously
        // fixme: send the event if it is not null after the token was sent! and log failure otherwise
        String tokenHash = sha512(token); // TODO: ideally don't store this in env var
        // TODO: store as cookie
        // TODO: I'd like this cookie to use different enc key or be more random, maybe just a hash?
        //      the issue is that we just give it anyone, regardless whether the user exists or not!
        //      should be go to the database instead first, after all??? probably no!
        //      MAYBE WE SHOULD ENCRYPT IT TWICE, once with the token, second time with the enc key!!
        //      this way, users can only get take on our enc key if they have the token
        //      that is, if they received email because they were in the database!!!
        // FIXME: the token may only be stored as a hashcode in the cookie!!
        // FIXME: limit TTL for the cookie validity, possibly make it configurable and default should be 6 minutes
        return Uni.createFrom().voidItem();
    }

    @Override
    public Uni<String> findPrincipalNameByToken(String token, RoutingContext routingContext) {
        PersistentLoginManager persistentLoginManager = getPersistentLoginManager(routingContext);

        // FIXME: decrypt token!! salt!
        // FIXME: decode token -> if not possible then completion exception
        // FIXME: decoded token -> validate timestamp, and use username to authenticate
        // FIXME: remove cookie!!!!!!

        // FIXME: impl. me! and remove the comments
        // so how does it work????
        // 1. if session cookie -> treat as any other form-based auth mech, that is:
        //      -> auth
        //      -> allow to send a new request for token if a different principal
        //      -> allow to accept another token if a different from current principal
        // 2. if post page -> require token or fail
        // 3. if token generation path -> require principal or fail!
        // 4. if no session cookie, redirect to login page or 401
        // 5. on auth failure etc. redirect to error page
        return Uni.createFrom().nullItem();
    }

    static void addPersistentLoginManager(RoutingContext routingContext, PersistentLoginManager loginManager) {
        routingContext.put(PERSISTENT_LOGIN_MANAGER_KEY, loginManager);
    }

    static void removePersistentLoginManager(RoutingContext routingContext, PersistentLoginManager loginManager) {
        routingContext.remove(PERSISTENT_LOGIN_MANAGER_KEY);
    }

    private static PersistentLoginManager getPersistentLoginManager(RoutingContext routingContext) {
        return routingContext.get(PERSISTENT_LOGIN_MANAGER_KEY);
    }

    private static String sha512(char[] token) {
        // this is only safe for UTF-8 because we use only chars from SAFE_TOKEN_CHARS
        byte[] bytes = new byte[token.length];
        try {
            for (int i = 0; i < token.length; i++) {
                bytes[i] = (byte) token[i];
            }
            return HashUtil.sha512(bytes);
        } finally {
            Arrays.fill(bytes, (byte) 0);
        }
    }
}
