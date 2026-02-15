package io.quarkus.vertx.http.runtime.security;

import java.util.Arrays;

import org.jboss.logging.Logger;

import io.quarkus.runtime.util.HashUtil;
import io.quarkus.vertx.http.runtime.FormAuthConfig;
import io.quarkus.vertx.http.security.form.token.FormAuthenticationTokenStorage;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

final class CookieFormAuthenticationTokenStorage implements FormAuthenticationTokenStorage {

    private static final Logger LOG = Logger.getLogger(CookieFormAuthenticationTokenStorage.class);
    private static final char PRINCIPAL_TO_TOKEN_SEPARATOR = '-';
    private static final String PERSISTENT_LOGIN_MANAGER_KEY = "io.quarkus.vertx.http.runtime.security#login-manager";
    private final String cookieName;
    private final long maxAgeSeconds;
    private final long timeoutMillis;

    CookieFormAuthenticationTokenStorage(FormAuthConfig.FormAuthenticationToken tokenConfig) {
        this.cookieName = tokenConfig.cookieName();
        this.maxAgeSeconds = tokenConfig.expiresIn().toSeconds();
        this.timeoutMillis = tokenConfig.expiresIn().toMillis();
    }

    @Override
    public Uni<Void> storeToken(char[] token, String principalName, RoutingContext event) {
        PersistentLoginManager loginManager = getPersistentLoginManager(event);
        loginManager.save(createCookieValue(token, principalName), event, cookieName, null, event.request().isSSL(),
                timeoutMillis, maxAgeSeconds);
        LOG.tracef("Stored form authentication token and principal name '%s' in cookie '%s'", principalName, cookieName);
        return Uni.createFrom().voidItem();
    }

    @Override
    public Uni<String> findPrincipalNameByToken(String token, RoutingContext routingContext) {
        PersistentLoginManager loginManager = getPersistentLoginManager(routingContext);
        String tokenRequest = loginManager.getAndRemoveCookie(cookieName, routingContext);
        if (tokenRequest == null) {
            LOG.tracef("Found no valid cookie '%s' for form authentication token '%s'", cookieName, token);
            return Uni.createFrom().nullItem();
        }
        var separatorIndex = tokenRequest.indexOf(PRINCIPAL_TO_TOKEN_SEPARATOR);
        if (separatorIndex == -1) {
            return Uni.createFrom()
                    .failure(new IllegalStateException("Token request cookie '" + cookieName + "' has invalid format"));
        }
        String principalName = tokenRequest.substring(0, separatorIndex);
        String expectedTokenHash = tokenRequest.substring(separatorIndex + 1);
        String receivedTokenHash = HashUtil.sha512(token);

        if (expectedTokenHash.equals(receivedTokenHash)) {
            LOG.tracef("Received correct token '%s' for principal name '%s'", token, principalName);
            return Uni.createFrom().item(principalName);
        }

        LOG.tracef("Received wrong token '%s' for principal name '%s', received token hash '%s' does not match"
                + " expected token hash '%s'", token, principalName, receivedTokenHash, expectedTokenHash);
        return Uni.createFrom().nullItem();
    }

    static void addPersistentLoginManager(RoutingContext routingContext, PersistentLoginManager loginManager) {
        routingContext.put(PERSISTENT_LOGIN_MANAGER_KEY, loginManager);
    }

    static void removePersistentLoginManager(RoutingContext routingContext) {
        routingContext.remove(PERSISTENT_LOGIN_MANAGER_KEY);
    }

    private static PersistentLoginManager getPersistentLoginManager(RoutingContext routingContext) {
        return routingContext.get(PERSISTENT_LOGIN_MANAGER_KEY);
    }

    private static String sha512(char[] token) {
        // this is only safe for UTF-8 because we use only chars from FormAuthenticationTokenHandler#SAFE_TOKEN_CHARS
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

    private static String createCookieValue(char[] token, String principalName) {
        return principalName + PRINCIPAL_TO_TOKEN_SEPARATOR + sha512(token);
    }
}
