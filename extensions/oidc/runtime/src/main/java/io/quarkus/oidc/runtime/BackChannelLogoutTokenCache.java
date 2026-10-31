package io.quarkus.oidc.runtime;

import org.eclipse.microprofile.jwt.Claims;
import org.jboss.logging.Logger;

import io.quarkus.oidc.common.runtime.OidcConstants;
import io.vertx.core.Vertx;
import io.vertx.core.json.JsonObject;

public class BackChannelLogoutTokenCache {

    private static final Logger LOG = Logger.getLogger(BackChannelLogoutTokenCache.class);
    private static final String CACHE_KEY_SEPARATOR = "|";

    private final MemoryCache<TokenVerificationResult> cache;
    private final String logoutTokenKey;
    private final boolean logoutTokenKeyIsSid;
    private final boolean logoutAllSessions;

    public BackChannelLogoutTokenCache(OidcTenantConfig oidcTenantConfig, Vertx vertx) {
        OidcTenantConfig.Backchannel backchannel = oidcTenantConfig.logout().backchannel();
        cache = new MemoryCache<>(vertx, backchannel.cleanUpTimerInterval(),
                backchannel.tokenCacheTimeToLive(), backchannel.tokenCacheSize());
        logoutTokenKey = backchannel.logoutTokenKey();
        logoutTokenKeyIsSid = OidcConstants.BACK_CHANNEL_LOGOUT_SID_CLAIM.equals(logoutTokenKey);
        logoutAllSessions = backchannel.logoutAllSessions();
    }

    public void addTokenVerification(TokenVerificationResult logoutToken) {
        JsonObject claims = logoutToken.localVerificationResult();
        String cacheKey = cacheKey(claims);
        TokenVerificationResult cachedLogoutToken = cache.get(cacheKey);
        if (cachedLogoutToken != null && isIssuedAfter(cachedLogoutToken.localVerificationResult(), claims)) {
            // logout tokens can arrive out of order, the latest one must win
            return;
        }
        cache.add(cacheKey, logoutToken);
    }

    public TokenVerificationResult findLogoutToken(JsonObject idTokenJson) {
        String logoutTokenKeyValue = idTokenJson.getString(logoutTokenKey);
        if (logoutTokenKeyValue == null) {
            return null;
        }
        TokenVerificationResult logoutToken = null;
        if (!logoutTokenKeyIsSid) {
            String idTokenSid = idTokenJson.getString(OidcConstants.ID_TOKEN_SID_CLAIM);
            if (idTokenSid != null) {
                // logout token with the session id targets only the session identified by it
                logoutToken = findLogoutToken(sessionCacheKey(logoutTokenKeyValue, idTokenSid), idTokenJson);
            }
        }
        if (logoutToken == null) {
            // logout token without the session id targets all the sessions of the subject
            logoutToken = findLogoutToken(logoutTokenKeyValue, idTokenJson);
        }
        return logoutToken;
    }

    public void logoutCompleted(TokenVerificationResult logoutToken) {
        JsonObject claims = logoutToken.localVerificationResult();
        if (logoutAllSessions && claims.getString(OidcConstants.BACK_CHANNEL_LOGOUT_SID_CLAIM) == null) {
            return;
        }
        cache.remove(cacheKey(claims));
    }

    void shutdown(Vertx vertx) {
        cache.stopTimer(vertx);
    }

    private TokenVerificationResult findLogoutToken(String cacheKey, JsonObject idTokenJson) {
        TokenVerificationResult logoutToken = cache.get(cacheKey);
        if (logoutToken != null && targetsSession(logoutToken.localVerificationResult(), idTokenJson)) {
            return logoutToken;
        }
        return null;
    }

    private String cacheKey(JsonObject logoutTokenJson) {
        String logoutTokenKeyValue = logoutTokenJson.getString(logoutTokenKey);
        if (logoutTokenKeyIsSid) {
            return logoutTokenKeyValue;
        }
        String logoutTokenSid = logoutTokenJson.getString(OidcConstants.BACK_CHANNEL_LOGOUT_SID_CLAIM);
        return logoutTokenSid == null ? logoutTokenKeyValue : sessionCacheKey(logoutTokenKeyValue, logoutTokenSid);
    }

    private static String sessionCacheKey(String logoutTokenKeyValue, String sid) {
        // the key is only an index, a collision is harmless because targetsSession
        // compares the subject and the session id claims separately
        return logoutTokenKeyValue + CACHE_KEY_SEPARATOR + sid;
    }

    private static boolean targetsSession(JsonObject logoutTokenJson, JsonObject idTokenJson) {
        String logoutTokenIss = logoutTokenJson.getString(Claims.iss.name());
        if (logoutTokenIss != null && !logoutTokenIss.equals(idTokenJson.getString(Claims.iss.name()))) {
            LOG.debug("Logout token issuer does not match the ID token issuer");
            return false;
        }
        String logoutTokenSub = logoutTokenJson.getString(Claims.sub.name());
        String idTokenSub = idTokenJson.getString(Claims.sub.name());
        if (logoutTokenSub != null && idTokenSub != null && !logoutTokenSub.equals(idTokenSub)) {
            LOG.debug("Logout token subject does not match the ID token subject");
            return false;
        }
        String logoutTokenSid = logoutTokenJson.getString(OidcConstants.BACK_CHANNEL_LOGOUT_SID_CLAIM);
        String idTokenSid = idTokenJson.getString(OidcConstants.ID_TOKEN_SID_CLAIM);
        if (logoutTokenSid != null && idTokenSid != null && !logoutTokenSid.equals(idTokenSid)) {
            LOG.debug("Logout token session id does not match the ID token session id");
            return false;
        }
        if (logoutTokenSid == null && isIssuedAfter(idTokenJson, logoutTokenJson)) {
            LOG.trace("ID token was issued after the logout token, the session is not affected");
            return false;
        }
        return true;
    }

    private static boolean isIssuedAfter(JsonObject token, JsonObject referenceToken) {
        Long tokenIssuedAt = token.getLong(Claims.iat.name());
        Long referenceTokenIssuedAt = referenceToken.getLong(Claims.iat.name());
        return tokenIssuedAt != null && referenceTokenIssuedAt != null && tokenIssuedAt > referenceTokenIssuedAt;
    }
}
