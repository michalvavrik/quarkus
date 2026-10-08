package io.quarkus.oidc.client.runtime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.junit.jupiter.api.Test;

import io.quarkus.oidc.client.Tokens;
import io.quarkus.oidc.client.runtime.RecordingOidcClient.Call;
import io.quarkus.oidc.client.runtime.RecordingOidcClient.Expiry;
import io.quarkus.oidc.common.runtime.OidcConstants;
import io.smallrye.mutiny.Uni;

/**
 * Unit test of the {@link TokensHelper} token cache.
 * <p>
 * The tests only use the public API of the helper so that they stay valid whatever the internal structure of the
 * cache is. The first group pins down the behaviour which must keep working once the cache takes the additional
 * parameters into account, the second group describes how the cache must behave for the additional parameters.
 */
public class TokensHelperTest {

    private static final Duration TIMEOUT = Duration.ofSeconds(5);
    private static final Map<String, String> NO_PARAMS = Map.of();
    private static final Map<String, String> SCOPE_A = Map.of("scope", "a");
    private static final Map<String, String> SCOPE_B = Map.of("scope", "b");

    private final RecordingOidcClient client = new RecordingOidcClient();
    private final TokensHelper helper = new TokensHelper();

    // Behaviour of the cache for a single set of parameters

    @Test
    public void testFirstCallAcquiresTokensAndSecondCallIsCacheHit() {
        // the first call issues a grant request carrying the parameters, the next call with the same parameters is
        // served from the cache
        Tokens first = getTokens(SCOPE_A);
        Tokens second = getTokens(SCOPE_A);

        assertIssuedFor(first, SCOPE_A);
        assertThat(second.getAccessToken()).isEqualTo(first.getAccessToken());
        assertThat(client.requests()).hasSize(1);
        assertThat(client.requests().get(0).isGrant()).isTrue();
        assertThat(client.requests().get(0).params()).isEqualTo(SCOPE_A);
    }

    @Test
    public void testInitTokensPrePopulatesCache() {
        // early token acquisition fills the cache so that the first getTokens call is a cache hit
        helper.initTokens(client, SCOPE_A);
        assertThat(client.requests()).hasSize(1);

        Tokens tokens = getTokens(SCOPE_A);

        assertIssuedFor(tokens, SCOPE_A);
        assertThat(client.requests()).hasSize(1);
    }

    @Test
    public void testInitTokensWithoutParametersPrePopulatesCacheForNoParameters() {
        // the overloads without parameters are equivalent to passing an empty map
        helper.initTokens(client);
        assertThat(client.requests()).hasSize(1);

        Tokens tokens = helper.getTokens(client).await().atMost(TIMEOUT);

        assertIssuedFor(tokens, NO_PARAMS);
        assertThat(client.requests()).hasSize(1);
    }

    @Test
    public void testExpiredAccessTokenIsRefreshedWithRefreshTokenAndParameters() {
        // an expired access token with a valid refresh token leads to a refresh token grant which carries the
        // parameters, the refreshed tokens replace the expired ones
        client.issue(Expiry.ACCESS_TOKEN_EXPIRED);
        Tokens expired = getTokens(SCOPE_A);
        client.issue(Expiry.VALID);

        Tokens refreshed = getTokens(SCOPE_A);

        assertIssuedFor(refreshed, SCOPE_A);
        assertThat(refreshed.getAccessToken()).isNotEqualTo(expired.getAccessToken());
        assertThat(client.requests()).hasSize(2);
        Call refresh = client.requests().get(1);
        assertThat(refresh.isRefresh()).isTrue();
        assertThat(refresh.refreshToken()).isEqualTo(expired.getRefreshToken());
        assertThat(refresh.params()).isEqualTo(SCOPE_A);

        Tokens cached = getTokens(SCOPE_A);
        assertThat(cached.getAccessToken()).isEqualTo(refreshed.getAccessToken());
        assertThat(client.requests()).hasSize(2);
    }

    @Test
    public void testExpiredAccessTokenWithoutRefreshTokenLeadsToNewGrant() {
        // no refresh token: a new grant request is made instead of a refresh
        client.issue(Expiry.ACCESS_TOKEN_EXPIRED_NO_REFRESH_TOKEN);
        Tokens expired = getTokens(SCOPE_A);
        client.issue(Expiry.VALID);

        Tokens renewed = getTokens(SCOPE_A);

        assertIssuedFor(renewed, SCOPE_A);
        assertThat(renewed.getAccessToken()).isNotEqualTo(expired.getAccessToken());
        assertThat(client.requests()).hasSize(2);
        assertThat(client.requests().get(1).isGrant()).isTrue();
        assertThat(client.requests().get(1).params()).isEqualTo(SCOPE_A);
    }

    @Test
    public void testExpiredAccessTokenWithExpiredRefreshTokenLeadsToNewGrant() {
        // expired refresh token: a new grant request is made instead of a refresh
        client.issue(Expiry.ACCESS_AND_REFRESH_TOKENS_EXPIRED);
        Tokens expired = getTokens(SCOPE_A);
        client.issue(Expiry.VALID);

        Tokens renewed = getTokens(SCOPE_A);

        assertIssuedFor(renewed, SCOPE_A);
        assertThat(renewed.getAccessToken()).isNotEqualTo(expired.getAccessToken());
        assertThat(client.requests()).hasSize(2);
        assertThat(client.requests().get(1).isGrant()).isTrue();
        assertThat(client.requests().get(1).params()).isEqualTo(SCOPE_A);
    }

    @Test
    public void testAccessTokenWithinRefreshIntervalIsRefreshedProactively() {
        // a still valid access token which is about to expire within the refresh token time skew is refreshed
        client.issue(Expiry.ACCESS_TOKEN_WITHIN_REFRESH_INTERVAL);
        Tokens aboutToExpire = getTokens(SCOPE_A);
        client.issue(Expiry.VALID);

        Tokens refreshed = getTokens(SCOPE_A);

        assertIssuedFor(refreshed, SCOPE_A);
        assertThat(refreshed.getAccessToken()).isNotEqualTo(aboutToExpire.getAccessToken());
        assertThat(client.requests()).hasSize(2);
        assertThat(client.requests().get(1).isRefresh()).isTrue();
        assertThat(client.requests().get(1).refreshToken()).isEqualTo(aboutToExpire.getRefreshToken());
    }

    @Test
    public void testForceNewTokensDiscardsValidCachedTokens() {
        // forcing new tokens issues a new grant request even though the cached tokens are valid, the refresh token
        // is not used and the new tokens replace the cached ones
        Tokens first = getTokens(SCOPE_A);

        Tokens forced = helper.getTokens(client, SCOPE_A, true).await().atMost(TIMEOUT);

        assertIssuedFor(forced, SCOPE_A);
        assertThat(forced.getAccessToken()).isNotEqualTo(first.getAccessToken());
        assertThat(client.requests()).hasSize(2);
        assertThat(client.requests().get(1).isGrant()).isTrue();
        assertThat(client.requests().get(1).params()).isEqualTo(SCOPE_A);

        Tokens cached = getTokens(SCOPE_A);
        assertThat(cached.getAccessToken()).isEqualTo(forced.getAccessToken());
        assertThat(client.requests()).hasSize(2);
    }

    @Test
    public void testCallsWithSameParametersJoinInFlightRequest() throws Exception {
        // while a request is in flight, another call with the same parameters joins it instead of starting a
        // second request
        client.respondLater();
        CompletableFuture<Tokens> first = subscribe(helper.getTokens(client, SCOPE_A, false));
        CompletableFuture<Tokens> second = subscribe(helper.getTokens(client, SCOPE_A, false));
        assertThat(client.requests()).hasSize(1);

        client.completePendingRequests();

        assertIssuedFor(await(first), SCOPE_A);
        assertThat(await(second).getAccessToken()).isEqualTo(await(first).getAccessToken());
        assertThat(client.requests()).hasSize(1);
    }

    @Test
    public void testReturnedUniIsMemoized() throws Exception {
        // subscribing more than once to the Uni returned while the request is in flight does not repeat the request
        client.respondLater();
        Uni<Tokens> uni = helper.getTokens(client, SCOPE_A, false);
        CompletableFuture<Tokens> first = subscribe(uni);
        CompletableFuture<Tokens> second = subscribe(uni);
        assertThat(client.requests()).hasSize(1);

        client.completePendingRequests();

        assertThat(await(first).getAccessToken()).isEqualTo(await(second).getAccessToken());
        assertThat(client.requests()).hasSize(1);
    }

    @Test
    public void testFailedRequestIsPropagatedAndNextCallRequestsTokensAgain() {
        // a failed request is reported to the caller and does not poison the cache: the next call makes a new
        // request which succeeds
        client.failRequests(() -> new IllegalStateException("token endpoint unavailable"));
        assertThatThrownBy(() -> getTokens(SCOPE_A))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("token endpoint unavailable");
        client.succeedRequests();

        Tokens tokens = getTokens(SCOPE_A);

        assertIssuedFor(tokens, SCOPE_A);
        assertThat(client.requests()).hasSize(2);
        assertThat(client.requests().get(1).params()).isEqualTo(SCOPE_A);
    }

    @Test
    public void testFailedInFlightRequestFailsAllWaitersAndNextCallRequestsTokensAgain() throws Exception {
        // every caller waiting for an in-flight request gets its failure, the next call makes a new request
        client.respondLater();
        CompletableFuture<Tokens> first = subscribe(helper.getTokens(client, SCOPE_A, false));
        CompletableFuture<Tokens> second = subscribe(helper.getTokens(client, SCOPE_A, false));
        assertThat(client.requests()).hasSize(1);

        client.failPendingRequests(new IllegalStateException("token endpoint unavailable"));

        assertThatThrownBy(() -> await(first)).hasCauseInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> await(second)).hasCauseInstanceOf(IllegalStateException.class);
        client.respondImmediately();
        assertIssuedFor(getTokens(SCOPE_A), SCOPE_A);
        assertThat(client.requests()).hasSize(2);
    }

    @Test
    public void testConcurrentCallsWithSameParametersMakeSingleRequest() throws Exception {
        // many threads asking for tokens at the same time result in a single request, every thread gets the tokens
        client.respondLater();

        List<Tokens> results = getTokensConcurrently(Collections.nCopies(50, SCOPE_A));

        assertThat(client.requests()).hasSize(1);
        for (Tokens tokens : results) {
            assertIssuedFor(tokens, SCOPE_A);
            assertThat(tokens.getAccessToken()).isEqualTo(results.get(0).getAccessToken());
        }
    }

    // Behaviour of the cache for different sets of parameters

    @Test
    public void testCallWithDifferentParametersDoesNotReturnCachedTokens() {
        // tokens cached for one set of parameters must not be returned for another set of parameters, a new grant
        // request carrying the new parameters must be made instead
        Tokens forA = getTokens(SCOPE_A);

        Tokens forB = getTokens(SCOPE_B);

        assertIssuedFor(forA, SCOPE_A);
        assertIssuedFor(forB, SCOPE_B);
        assertThat(client.requests()).hasSize(2);
        assertThat(client.requests().get(1).isGrant()).isTrue();
        assertThat(client.requests().get(1).params()).isEqualTo(SCOPE_B);
    }

    @Test
    public void testTokensAreCachedPerParameters() {
        // This is the assertion which distinguishes a keyed cache from a single entry which merely remembers the
        // parameters it was acquired with: once tokens were acquired for two sets of parameters, switching back and
        // forth between them is served from the cache without any new request
        Tokens forA = getTokens(SCOPE_A);
        Tokens forB = getTokens(SCOPE_B);
        assertIssuedFor(forA, SCOPE_A);
        assertIssuedFor(forB, SCOPE_B);
        assertThat(client.requests()).hasSize(2);

        Tokens forAAgain = getTokens(SCOPE_A);
        Tokens forBAgain = getTokens(SCOPE_B);

        assertThat(forAAgain.getAccessToken()).isEqualTo(forA.getAccessToken());
        assertThat(forBAgain.getAccessToken()).isEqualTo(forB.getAccessToken());
        assertThat(client.requests()).hasSize(2);
    }

    @Test
    public void testCallWithDifferentParametersDoesNotJoinInFlightRequest() throws Exception {
        // a call must only join an in-flight request made with the same parameters, otherwise it must make its own
        // request
        client.respondLater();
        CompletableFuture<Tokens> forA = subscribe(helper.getTokens(client, SCOPE_A, false));
        CompletableFuture<Tokens> forB = subscribe(helper.getTokens(client, SCOPE_B, false));

        client.completePendingRequests();

        assertIssuedFor(await(forA), SCOPE_A);
        assertIssuedFor(await(forB), SCOPE_B);
        assertThat(client.requests()).extracting(Call::params).containsExactly(SCOPE_A, SCOPE_B);
    }

    @Test
    public void testForceNewTokensDoesNotJoinInFlightRequestWithDifferentParameters() throws Exception {
        // forcing new tokens must never return tokens requested with other parameters either
        client.respondLater();
        CompletableFuture<Tokens> forA = subscribe(helper.getTokens(client, SCOPE_A, true));
        CompletableFuture<Tokens> forB = subscribe(helper.getTokens(client, SCOPE_B, true));

        client.completePendingRequests();

        assertIssuedFor(await(forA), SCOPE_A);
        assertIssuedFor(await(forB), SCOPE_B);
        assertThat(client.requests()).extracting(Call::params).containsExactly(SCOPE_A, SCOPE_B);
    }

    @Test
    public void testExpiredTokensAreRefreshedWithTheirOwnRefreshTokenAndParameters() {
        // the refresh of the tokens cached for one set of parameters uses the refresh token and the parameters of
        // that entry and does not affect the tokens cached for other parameters
        client.issue(Expiry.ACCESS_TOKEN_EXPIRED);
        Tokens expiredForA = getTokens(SCOPE_A);
        client.issue(Expiry.VALID);
        Tokens forB = getTokens(SCOPE_B);
        assertIssuedFor(forB, SCOPE_B);
        assertThat(client.requests()).hasSize(2);

        Tokens refreshedForA = getTokens(SCOPE_A);

        assertIssuedFor(refreshedForA, SCOPE_A);
        assertThat(refreshedForA.getAccessToken()).isNotEqualTo(expiredForA.getAccessToken());
        assertThat(client.requests()).hasSize(3);
        Call refresh = client.requests().get(2);
        assertThat(refresh.isRefresh()).isTrue();
        assertThat(refresh.refreshToken()).isEqualTo(expiredForA.getRefreshToken());
        assertThat(refresh.params()).isEqualTo(SCOPE_A);

        Tokens forBAgain = getTokens(SCOPE_B);
        assertThat(forBAgain.getAccessToken()).isEqualTo(forB.getAccessToken());
        assertThat(client.requests()).hasSize(3);
    }

    @Test
    public void testExpiredTokensAreNotRefreshedForDifferentParameters() {
        // a call with parameters no tokens were acquired for yet must make a new grant request with these
        // parameters, it must not send the refresh token issued for other parameters
        client.issue(Expiry.ACCESS_TOKEN_EXPIRED);
        Tokens expiredForA = getTokens(SCOPE_A);
        client.issue(Expiry.VALID);

        Tokens forB = getTokens(SCOPE_B);

        assertIssuedFor(forB, SCOPE_B);
        assertThat(client.requests()).hasSize(2);
        Call request = client.requests().get(1);
        assertThat(request.isGrant())
                .as("expected a new grant request for %s but got %s with the refresh token issued for %s",
                        SCOPE_B, request, SCOPE_A)
                .isTrue();
        assertThat(request.params()).isEqualTo(SCOPE_B);
        assertThat(client.calls()).extracting(Call::refreshToken).doesNotContain(expiredForA.getRefreshToken());
    }

    @Test
    public void testFailedRequestForDifferentParametersLeavesCachedTokensIntact() {
        // a failed request for one set of parameters does not affect the tokens cached for other parameters
        Tokens forA = getTokens(SCOPE_A);
        client.failRequests(() -> new IllegalStateException("token endpoint unavailable"));

        assertThatThrownBy(() -> getTokens(SCOPE_B),
                "expected the request for %s to fail instead of returning the tokens cached for %s", SCOPE_B, SCOPE_A)
                .isInstanceOf(IllegalStateException.class);

        client.succeedRequests();
        Tokens forAAgain = getTokens(SCOPE_A);
        assertThat(forAAgain.getAccessToken()).isEqualTo(forA.getAccessToken());
        assertThat(client.requests()).hasSize(2);
    }

    @Test
    public void testForceNewTokensCarriesParameters() {
        // every forced acquisition is a new grant request carrying the parameters of that call
        Tokens forA = helper.getTokens(client, SCOPE_A, true).await().atMost(TIMEOUT);
        Tokens forB = helper.getTokens(client, SCOPE_B, true).await().atMost(TIMEOUT);
        Tokens forAAgain = helper.getTokens(client, SCOPE_A, true).await().atMost(TIMEOUT);

        assertIssuedFor(forA, SCOPE_A);
        assertIssuedFor(forB, SCOPE_B);
        assertIssuedFor(forAAgain, SCOPE_A);
        assertThat(forAAgain.getAccessToken()).isNotEqualTo(forA.getAccessToken());
        assertThat(client.requests()).extracting(Call::params).containsExactly(SCOPE_A, SCOPE_B, SCOPE_A);
        assertThat(client.requests()).allMatch(Call::isGrant);
    }

    @Test
    public void testParametersWithEqualContentShareCachedTokens() {
        // parameters are compared by content, the map implementation and the insertion order do not matter
        Map<String, String> immutable = Map.of("scope", "a", "audience", "x");
        Map<String, String> reversed = new LinkedHashMap<>();
        reversed.put("audience", "x");
        reversed.put("scope", "a");
        Map<String, String> sorted = new TreeMap<>(immutable);

        Tokens first = getTokens(immutable);
        Tokens second = getTokens(reversed);
        Tokens third = getTokens(sorted);

        assertIssuedFor(first, immutable);
        assertThat(second.getAccessToken()).isEqualTo(first.getAccessToken());
        assertThat(third.getAccessToken()).isEqualTo(first.getAccessToken());
        assertThat(client.requests()).hasSize(1);
    }

    @Test
    public void testEmptyParameterVariantsShareCachedTokens() {
        // all the ways of passing no parameters share the same cached tokens
        Tokens first = helper.getTokens(client).await().atMost(TIMEOUT);
        Tokens second = getTokens(Map.of());
        Tokens third = getTokens(Collections.emptyMap());
        Tokens fourth = getTokens(new HashMap<>());

        assertIssuedFor(first, NO_PARAMS);
        assertThat(second.getAccessToken()).isEqualTo(first.getAccessToken());
        assertThat(third.getAccessToken()).isEqualTo(first.getAccessToken());
        assertThat(fourth.getAccessToken()).isEqualTo(first.getAccessToken());
        assertThat(client.requests()).hasSize(1);
    }

    @Test
    public void testDifferentValueOrAdditionalParameterIsDifferentCacheEntry() {
        // a different value for the same parameter, or an additional parameter, is a different set of parameters
        Map<String, String> scopeAWithAudience = Map.of("scope", "a", "audience", "x");

        Tokens forA = getTokens(SCOPE_A);
        Tokens forB = getTokens(SCOPE_B);
        Tokens forAWithAudience = getTokens(scopeAWithAudience);

        assertIssuedFor(forA, SCOPE_A);
        assertIssuedFor(forB, SCOPE_B);
        assertIssuedFor(forAWithAudience, scopeAWithAudience);
        assertThat(client.requests()).extracting(Call::params).containsExactly(SCOPE_A, SCOPE_B, scopeAWithAudience);
    }

    @Test
    public void testCacheIsNotAffectedByCallerMutatingParametersAfterCall() {
        // Design requirement: the cache must keep its own copy of the parameters, a caller mutating the map after
        // the call must not change which tokens the entry is for
        Map<String, String> mutable = new HashMap<>(SCOPE_A);
        Tokens forA = getTokens(mutable);
        mutable.put("scope", "b");

        Tokens forAAgain = getTokens(SCOPE_A);
        assertThat(forAAgain.getAccessToken()).isEqualTo(forA.getAccessToken());
        assertThat(client.requests()).hasSize(1);

        Tokens forB = getTokens(SCOPE_B);
        assertIssuedFor(forB, SCOPE_B);
        assertThat(client.requests()).hasSize(2);
        assertThat(client.requests().get(1).params()).isEqualTo(SCOPE_B);
    }

    @Test
    public void testInitTokensWithParametersDoesNotServeCallWithDifferentParameters() {
        // early acquired tokens are only valid for the parameters they were acquired with
        helper.initTokens(client, SCOPE_A);

        Tokens forB = getTokens(SCOPE_B);

        assertIssuedFor(forB, SCOPE_B);
        assertThat(client.requests()).hasSize(2);
        assertThat(client.requests().get(1).isGrant()).isTrue();
        assertThat(client.requests().get(1).params()).isEqualTo(SCOPE_B);
    }

    @Test
    public void testConcurrentCallsWithDifferentParametersMakeOneRequestPerParameters() throws Exception {
        // threads asking for tokens with two different sets of parameters at the same time result in exactly one
        // request per set of parameters, every thread gets the tokens issued for its own parameters
        client.respondLater();
        List<Map<String, String>> paramsPerThread = new ArrayList<>();
        for (int i = 0; i < 25; i++) {
            paramsPerThread.add(SCOPE_A);
            paramsPerThread.add(SCOPE_B);
        }

        List<Tokens> results = getTokensConcurrently(paramsPerThread);

        for (int i = 0; i < paramsPerThread.size(); i++) {
            assertIssuedFor(results.get(i), paramsPerThread.get(i));
        }
        assertThat(client.requests()).extracting(Call::params).containsExactlyInAnyOrder(SCOPE_A, SCOPE_B);
    }

    @Test
    public void testManyDifferentParametersGetTheirOwnTokens() {
        // request specific parameters, like a subject token, must each get their own tokens whatever the size of
        // the cache is, the eviction is covered by the tests below
        for (int i = 0; i < 100; i++) {
            Map<String, String> params = Map.of("subject_token", "subject-" + i);
            assertIssuedFor(getTokens(params), params);
        }
        assertThat(client.requests()).hasSize(100);
    }

    // Behaviour of the cache when it is full

    @Test
    public void testCacheIsBoundedAndTokensExpiringFirstAreEvicted() {
        // the cache holds the tokens of a limited number of sets of parameters, when it is full the tokens which
        // expire first are evicted to make room for the new ones and the other cached tokens are not affected
        List<Map<String, String>> params = parameterSets(TokensHelper.MAX_CACHED_PARAMETER_SETS);
        int max = params.size();
        for (Map<String, String> p : params) {
            assertIssuedFor(getTokens(p), p);
        }
        for (Map<String, String> p : params) {
            getTokens(p);
        }
        assertThat(client.requests()).hasSize(max);

        Map<String, String> oneMore = Map.of("scope", "one-more");
        assertIssuedFor(getTokens(oneMore), oneMore);
        assertThat(client.requests()).hasSize(max + 1);

        // the tokens acquired first expire first and were evicted, all the other tokens are still cached
        for (int i = 1; i < max; i++) {
            getTokens(params.get(i));
        }
        getTokens(oneMore);
        assertThat(client.requests()).hasSize(max + 1);
        assertIssuedFor(getTokens(params.get(0)), params.get(0));
        assertThat(client.requests()).hasSize(max + 2);
        // evicted together with the refresh token, so a new grant and not a refresh
        assertThat(client.requests().get(max + 1).isGrant()).isTrue();
    }

    @Test
    public void testFailedRequestsAreEvictedBeforeValidTokens() {
        // a failed request leaves nothing worth keeping, so it is evicted before any valid tokens
        List<Map<String, String>> params = parameterSets(TokensHelper.MAX_CACHED_PARAMETER_SETS - 1);
        for (Map<String, String> p : params) {
            getTokens(p);
        }
        Map<String, String> failing = Map.of("scope", "failing");
        client.failRequests(() -> new IllegalStateException("token endpoint unavailable"));
        assertThatThrownBy(() -> getTokens(failing)).isInstanceOf(IllegalStateException.class);
        client.succeedRequests();

        // the cache is full now, the next set of parameters evicts the failed one
        Map<String, String> oneMore = Map.of("scope", "one-more");
        assertIssuedFor(getTokens(oneMore), oneMore);
        int requests = client.requests().size();
        for (Map<String, String> p : params) {
            getTokens(p);
        }
        getTokens(oneMore);
        assertThat(client.requests()).hasSize(requests);
    }

    @Test
    public void testValidTokensAreEvictedBeforeRequestsInProgress() throws Exception {
        // the tokens being acquired are evicted after the valid tokens which expire first
        List<Map<String, String>> params = parameterSets(TokensHelper.MAX_CACHED_PARAMETER_SETS - 1);
        for (Map<String, String> p : params) {
            getTokens(p);
        }
        client.respondLater();
        Map<String, String> inProgress = Map.of("scope", "in-progress");
        CompletableFuture<Tokens> inProgressResult = subscribe(helper.getTokens(client, inProgress, false));
        Map<String, String> oneMore = Map.of("scope", "one-more");
        CompletableFuture<Tokens> oneMoreResult = subscribe(helper.getTokens(client, oneMore, false));
        client.completePendingRequests();
        assertIssuedFor(await(inProgressResult), inProgress);
        assertIssuedFor(await(oneMoreResult), oneMore);
        client.respondImmediately();

        // the tokens acquired first were evicted, everything else is still cached
        int requests = client.requests().size();
        getTokens(inProgress);
        getTokens(oneMore);
        for (int i = 1; i < params.size(); i++) {
            getTokens(params.get(i));
        }
        assertThat(client.requests()).hasSize(requests);
        assertIssuedFor(getTokens(params.get(0)), params.get(0));
        assertThat(client.requests()).hasSize(requests + 1);
    }

    @Test
    public void testRequestsInProgressAreEvictedLastAndStillDeliverTheirTokens() throws Exception {
        // the cache stays bounded even when it is full of requests in progress: one of them is evicted to make
        // room, the callers waiting for it still get their tokens, the tokens are just not cached
        client.respondLater();
        List<Map<String, String>> params = parameterSets(TokensHelper.MAX_CACHED_PARAMETER_SETS + 1);
        List<CompletableFuture<Tokens>> results = new ArrayList<>();
        for (Map<String, String> p : params) {
            results.add(subscribe(helper.getTokens(client, p, false)));
        }
        assertThat(client.requests()).hasSize(params.size());
        client.completePendingRequests();
        for (int i = 0; i < params.size(); i++) {
            assertIssuedFor(await(results.get(i)), params.get(i));
        }

        // exactly one set of parameters is not cached anymore
        client.respondImmediately();
        for (Map<String, String> p : params) {
            assertIssuedFor(getTokens(p), p);
        }
        assertThat(client.requests()).hasSize(params.size() + 1);
    }

    // Client assertion

    @Test
    public void testClientAssertionIsNotPartOfTheCacheKey() {
        // the client assertion authenticates the client and does not affect which tokens are issued: calls which
        // only differ by the client assertion share the cached tokens, while every request which is made carries
        // the client assertion of the caller which triggered it
        Map<String, String> firstAssertion = Map.of("scope", "a", OidcConstants.CLIENT_ASSERTION, "jwt-1",
                OidcConstants.CLIENT_ASSERTION_TYPE, OidcConstants.JWT_BEARER_CLIENT_ASSERTION_TYPE);
        Map<String, String> secondAssertion = Map.of("scope", "a", OidcConstants.CLIENT_ASSERTION, "jwt-2",
                OidcConstants.CLIENT_ASSERTION_TYPE, OidcConstants.JWT_BEARER_CLIENT_ASSERTION_TYPE);
        Map<String, String> thirdAssertion = Map.of("scope", "a", OidcConstants.CLIENT_ASSERTION, "jwt-3",
                OidcConstants.CLIENT_ASSERTION_TYPE, OidcConstants.JWT_BEARER_CLIENT_ASSERTION_TYPE);

        client.issue(Expiry.ACCESS_TOKEN_EXPIRED);
        Tokens expired = getTokens(firstAssertion);
        client.issue(Expiry.VALID);
        assertIssuedFor(expired, firstAssertion);
        assertThat(client.requests().get(0).params()).isEqualTo(firstAssertion);

        // same cached entry, expired, so refreshed with the refresh token of the entry and the current assertion
        Tokens refreshed = getTokens(secondAssertion);
        assertThat(client.requests()).hasSize(2);
        Call refresh = client.requests().get(1);
        assertThat(refresh.isRefresh()).isTrue();
        assertThat(refresh.refreshToken()).isEqualTo(expired.getRefreshToken());
        assertThat(refresh.params()).isEqualTo(secondAssertion);

        // cache hits, with yet another assertion and without any assertion
        assertThat(getTokens(thirdAssertion).getAccessToken()).isEqualTo(refreshed.getAccessToken());
        assertThat(getTokens(SCOPE_A).getAccessToken()).isEqualTo(refreshed.getAccessToken());
        assertThat(client.requests()).hasSize(2);

        // the other parameters still matter
        Map<String, String> otherScope = Map.of("scope", "b", OidcConstants.CLIENT_ASSERTION, "jwt-1");
        assertIssuedFor(getTokens(otherScope), otherScope);
        assertThat(client.requests()).hasSize(3);
    }

    private static List<Map<String, String>> parameterSets(int count) {
        List<Map<String, String>> params = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            params.add(Map.of("scope", "scope-" + i));
        }
        return params;
    }

    private Tokens getTokens(Map<String, String> params) {
        return helper.getTokens(client, params, false).await().atMost(TIMEOUT);
    }

    private static CompletableFuture<Tokens> subscribe(Uni<Tokens> uni) {
        return uni.subscribe().asCompletionStage();
    }

    private static Tokens await(CompletableFuture<Tokens> future)
            throws InterruptedException, ExecutionException, TimeoutException {
        return future.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS);
    }

    private List<Tokens> getTokensConcurrently(List<Map<String, String>> paramsPerThread) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(paramsPerThread.size());
        try {
            CountDownLatch start = new CountDownLatch(1);
            CountDownLatch requested = new CountDownLatch(paramsPerThread.size());
            List<Future<Tokens>> futures = new ArrayList<>();
            for (Map<String, String> params : paramsPerThread) {
                futures.add(executor.submit(new Callable<Tokens>() {
                    @Override
                    public Tokens call() throws Exception {
                        start.await();
                        CompletableFuture<Tokens> result = subscribe(helper.getTokens(client, params, false));
                        requested.countDown();
                        return await(result);
                    }
                }));
            }
            start.countDown();
            assertThat(requested.await(TIMEOUT.toSeconds(), TimeUnit.SECONDS)).isTrue();
            // every thread has subscribed, now let the token endpoint respond
            client.completePendingRequests();
            List<Tokens> results = new ArrayList<>();
            for (Future<Tokens> future : futures) {
                results.add(future.get(TIMEOUT.toSeconds(), TimeUnit.SECONDS));
            }
            return results;
        } finally {
            executor.shutdownNow();
        }
    }

    private static void assertIssuedFor(Tokens tokens, Map<String, String> params) {
        assertThat(tokens.getAccessToken())
                .as("access token must have been issued for the parameters %s", params)
                .startsWith(RecordingOidcClient.accessTokenPrefix(params));
    }
}
