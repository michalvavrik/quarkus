package io.quarkus.oidc.client.runtime;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReferenceFieldUpdater;
import java.util.function.BiConsumer;

import org.jboss.logging.Logger;

import io.quarkus.oidc.client.OidcClient;
import io.quarkus.oidc.client.Tokens;
import io.quarkus.oidc.common.runtime.OidcConstants;
import io.smallrye.mutiny.Uni;

public class TokensHelper {
    private static final Logger LOG = Logger.getLogger(TokensHelper.class);

    /**
     * Maximum number of sets of additional parameters the tokens are cached for.
     */
    static final int MAX_CACHED_PARAMETER_SETS = 15;

    private static final AtomicReferenceFieldUpdater<TokenRequestStateHolder, TokenRequestState> tokenRequestStateUpdater = AtomicReferenceFieldUpdater
            .newUpdater(TokenRequestStateHolder.class, TokenRequestState.class, "tokenRequestState");

    private static final Comparator<EvictionCandidate> EVICTION_ORDER = new Comparator<EvictionCandidate>() {
        @Override
        public int compare(EvictionCandidate first, EvictionCandidate second) {
            return Long.compare(first.evictionOrder(), second.evictionOrder());
        }
    };

    // the tokens are cached per set of additional parameters as the parameters can affect which tokens are issued,
    // each holder manages the token request state of one set of parameters
    private final ConcurrentHashMap<Map<String, String>, TokenRequestStateHolder> tokenRequestStateHolders = new ConcurrentHashMap<>();

    public void initTokens(OidcClient oidcClient) {
        initTokens(oidcClient, Map.of());
    }

    public void initTokens(OidcClient oidcClient, Map<String, String> additionalParameters) {
        //init the tokens, this just happens in a blocking manner for now
        tokenRequestStateUpdater.set(tokenRequestStateHolder(additionalParameters),
                new TokenRequestState(oidcClient.getTokens(additionalParameters).await().indefinitely()));
    }

    public Uni<Tokens> getTokens(OidcClient oidcClient) {
        return getTokens(oidcClient, Map.of(), false);
    }

    public Uni<Tokens> getTokens(OidcClient oidcClient, Map<String, String> additionalParameters, boolean forceNewTokens) {
        return getTokens(oidcClient, additionalParameters, forceNewTokens, tokenRequestStateHolder(additionalParameters));
    }

    private static Uni<Tokens> getTokens(OidcClient oidcClient, Map<String, String> additionalParameters,
            boolean forceNewTokens, TokenRequestStateHolder holder) {
        TokenRequestState currentState = null;
        TokenRequestState newState = null;
        //if the tokens are expired we refresh them in an async manner
        //we use CAS to make sure we only make a single request
        for (;;) {
            currentState = tokenRequestStateUpdater.get(holder);
            if (currentState == null) {
                //init the initial state
                //note that this can still happen at runtime as if there is an error then the state will be null
                newState = new TokenRequestState(prepareUni(oidcClient.getTokens(additionalParameters), holder));
                if (tokenRequestStateUpdater.compareAndSet(holder, currentState, newState)) {
                    return newState.tokenUni;
                }
                //rerun the CAS loop
            } else if (currentState.tokenUni != null) {
                return currentState.tokenUni;
            } else if (forceNewTokens) {
                LOG.debugf("Forcing acquisition of new tokens for client %s", currentState.tokens.getClientId());

                newState = new TokenRequestState(prepareUni(oidcClient.getTokens(additionalParameters), holder));
                if (tokenRequestStateUpdater.compareAndSet(holder, currentState, newState)) {
                    return newState.tokenUni;
                }
                //rerun the CAS loop
            } else {
                Tokens tokens = currentState.tokens;

                if (tokens.isAccessTokenExpired() || tokens.isAccessTokenWithinRefreshInterval()) {
                    LOG.debugf("Starting refreshing the tokens for client %s", tokens.getClientId());
                    final boolean refreshTokenValid = tokens.getRefreshToken() != null && !tokens.isRefreshTokenExpired();
                    if (!refreshTokenValid) {
                        LOG.debugf("Refresh token is not available or has expired, "
                                + "acquiring new tokens instead for client %s", tokens.getClientId());
                    }
                    newState = new TokenRequestState(
                            prepareUni(refreshTokenValid
                                    ? oidcClient.refreshTokens(tokens.getRefreshToken(), additionalParameters)
                                    : oidcClient.getTokens(additionalParameters), holder));
                    if (tokenRequestStateUpdater.compareAndSet(holder, currentState, newState)) {
                        return newState.tokenUni;
                    }
                    //rerun the CAS loop
                } else {
                    return Uni.createFrom().item(tokens);
                }
            }
        }
    }

    private static Uni<Tokens> prepareUni(Uni<Tokens> tokens, TokenRequestStateHolder holder) {
        return tokens.onItemOrFailure().invoke(new BiConsumer<Tokens, Throwable>() {
            @Override
            public void accept(Tokens tokens, Throwable throwable) {
                //we only have a single outstanding request per set of additional parameters
                //so we don't need to CAS
                if (tokens != null) {
                    tokenRequestStateUpdater.set(holder, new TokenRequestState(tokens));
                } else {
                    tokenRequestStateUpdater.set(holder, null);
                }
            }
        })
                // prevent next subscriptions to trigger multiple times the HTTP request before the end of the first one
                .memoize().indefinitely();
    }

    private TokenRequestStateHolder tokenRequestStateHolder(Map<String, String> additionalParameters) {
        // the map passed by the caller can be used to look the holder up, maps are compared by content
        Map<String, String> key = cacheKey(additionalParameters);
        TokenRequestStateHolder holder = tokenRequestStateHolders.get(key);
        if (holder == null) {
            if (tokenRequestStateHolders.mappingCount() >= MAX_CACHED_PARAMETER_SETS) {
                evictTokenRequestStateHolders();
            }
            TokenRequestStateHolder newHolder = new TokenRequestStateHolder();
            // the key must be an immutable copy as the caller can modify the map after the call
            holder = tokenRequestStateHolders.putIfAbsent(Map.copyOf(key), newHolder);
            if (holder == null) {
                holder = newHolder;
            }
        }
        return holder;
    }

    private static Map<String, String> cacheKey(Map<String, String> additionalParameters) {
        if (additionalParameters.containsKey(OidcConstants.CLIENT_ASSERTION)
                || additionalParameters.containsKey(OidcConstants.CLIENT_ASSERTION_TYPE)) {
            // the client assertion authenticates the client, it does not affect which tokens are issued,
            // and it is typically renewed for every request
            Map<String, String> key = new HashMap<>(additionalParameters);
            key.remove(OidcConstants.CLIENT_ASSERTION);
            key.remove(OidcConstants.CLIENT_ASSERTION_TYPE);
            return key;
        }
        return additionalParameters;
    }

    private void evictTokenRequestStateHolders() {
        // the cache is full, make room for one more set of additional parameters: the holders of the failed
        // requests are evicted first, then the holders of the tokens which expire first and finally the holders
        // of the requests in progress, which keeps the cache bounded even if every request is in progress.
        // Evicting the holder of a request in progress is safe, the tokens are still delivered to the callers
        // waiting for them, they are only not cached.
        // Only the atomic operations of the map are used so that concurrent evictions and concurrent additions
        // are safe, at worst one holder too many is evicted or the limit is temporarily exceeded by a few holders
        // which are evicted the next time the cache is full
        List<EvictionCandidate> candidates = new ArrayList<>();
        for (Map.Entry<Map<String, String>, TokenRequestStateHolder> entry : tokenRequestStateHolders.entrySet()) {
            TokenRequestState state = tokenRequestStateUpdater.get(entry.getValue());
            long evictionOrder;
            if (state == null) {
                evictionOrder = Long.MIN_VALUE;
            } else if (state.tokens == null) {
                evictionOrder = Long.MAX_VALUE;
            } else {
                Long accessTokenExpiresAt = state.tokens.getAccessTokenExpiresAt();
                evictionOrder = accessTokenExpiresAt == null ? Long.MAX_VALUE - 1 : accessTokenExpiresAt;
            }
            candidates.add(new EvictionCandidate(entry.getKey(), entry.getValue(), evictionOrder));
        }
        Collections.sort(candidates, EVICTION_ORDER);
        long holdersToEvict = tokenRequestStateHolders.mappingCount() - MAX_CACHED_PARAMETER_SETS + 1;
        if (holdersToEvict > 0) {
            LOG.debugf("Token cache is full, evicting the tokens of %d sets of additional parameters", holdersToEvict);
        }
        for (int i = 0; i < candidates.size() && holdersToEvict > 0; i++) {
            EvictionCandidate candidate = candidates.get(i);
            if (tokenRequestStateHolders.remove(candidate.key(), candidate.holder())) {
                holdersToEvict--;
            }
        }
    }

    static final class TokenRequestStateHolder {
        @SuppressWarnings("unused")
        private volatile TokenRequestState tokenRequestState;
    }

    static final class TokenRequestState {
        final Tokens tokens;
        final Uni<Tokens> tokenUni;

        TokenRequestState(Tokens tokens) {
            this.tokens = tokens;
            this.tokenUni = null;
        }

        TokenRequestState(Uni<Tokens> tokensUni) {
            this.tokens = null;
            this.tokenUni = tokensUni;
        }
    }

    private record EvictionCandidate(Map<String, String> key, TokenRequestStateHolder holder, long evictionOrder) {
    }
}
