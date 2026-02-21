package io.quarkus.email.authentication.runtime.internal;

import java.util.Arrays;

import jakarta.enterprise.context.ApplicationScoped;

import org.jboss.logging.Logger;

import io.quarkus.arc.DefaultBean;
import io.quarkus.email.authentication.EmailAuthenticationTokenStorage.DefaultEmailAuthenticationTokenStorage;
import io.quarkus.runtime.util.HashUtil;
import io.quarkus.vertx.http.runtime.security.PersistentLoginManager;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

@DefaultBean
@ApplicationScoped
class CookieEmailAuthenticationTokenStorage implements DefaultEmailAuthenticationTokenStorage {

    private static final Logger LOG = Logger.getLogger(CookieEmailAuthenticationTokenStorage.class);
    private static final char PRINCIPAL_TO_TOKEN_SEPARATOR = '-';
    private static final String PERSISTENT_LOGIN_MANAGER_KEY = "io.quarkus.email.authentication#login-manager";

    private final String cookieName;
    private final long maxAgeSeconds;
    private final long timeoutMillis;

    CookieEmailAuthenticationTokenStorage(EmailAuthenticationConfig config) {
        this.cookieName = config.tokenCookie();
        this.maxAgeSeconds = config.tokenExpiresIn().toSeconds();
        this.timeoutMillis = config.tokenExpiresIn().toMillis();
    }

    @Override
    public Uni<Void> storeToken(EmailAuthenticationTokenRequest tokenRequest, String principalName, RoutingContext event) {
        getLoginManager(event).save(createCookieValue(tokenRequest.token(), principalName), event, cookieName, null,
                event.request().isSSL(), timeoutMillis, maxAgeSeconds);
        LOG.tracef("Stored email authentication token and principal name '%s' in cookie '%s'", principalName, cookieName);
        return Uni.createFrom().voidItem();
    }

    @Override
    public Uni<String> findPrincipalNameByToken(String token, RoutingContext routingContext) {
        String tokenRequest = getLoginManager(routingContext).getAndRemoveCookie(cookieName, routingContext);
        if (tokenRequest == null) {
            LOG.tracef("Found no valid cookie '%s' for email authentication token '%s'", cookieName, token);
            return Uni.createFrom().nullItem();
        }
        var separatorIndex = tokenRequest.indexOf(PRINCIPAL_TO_TOKEN_SEPARATOR);
        if (separatorIndex == -1) {
            return Uni.createFrom().failure(new IllegalStateException(
                    "Email authentication token request cookie '" + cookieName + "' has invalid format: " + tokenRequest));
        }
        String principalName = tokenRequest.substring(0, separatorIndex);
        String expectedTokenHash = tokenRequest.substring(separatorIndex + 1);
        String receivedTokenHash = HashUtil.sha512(token);

        if (expectedTokenHash.equals(receivedTokenHash)) {
            LOG.tracef("Received correct email authentication token '%s' for principal name '%s'", token, principalName);
            return Uni.createFrom().item(principalName);
        }

        LOG.tracef("Received wrong token '%s' for principal name '%s', the received token hash '%s' does not match"
                + " the expected token hash '%s'", token, principalName, receivedTokenHash, expectedTokenHash);
        return Uni.createFrom().nullItem();
    }

    static void addPersistentLoginManager(RoutingContext routingContext, PersistentLoginManager loginManager) {
        routingContext.put(PERSISTENT_LOGIN_MANAGER_KEY, loginManager);
    }

    static void removePersistentLoginManager(RoutingContext routingContext) {
        routingContext.remove(PERSISTENT_LOGIN_MANAGER_KEY);
    }

    private static PersistentLoginManager getLoginManager(RoutingContext routingContext) {
        return routingContext.get(PERSISTENT_LOGIN_MANAGER_KEY);
    }

    private static String sha512(char[] token) {
        // this is safe for UTF-8 because we only expect chars from EmailAuthenticationMechanism#SAFE_TOKEN_CHARS
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
