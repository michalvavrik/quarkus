package io.quarkus.http.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkus.http.ratelimit.deployment.HttpRateLimitBuildConfigValidator;
import io.quarkus.http.ratelimit.runtime.internal.config.HttpRateLimitBuildTimeConfig;
import io.smallrye.config.SmallRyeConfigBuilder;

/**
 * Runs the build time validator against configurations built with SmallRye Config. It is a plain unit test, like the
 * validator it tests, which is a deployment class. The build step that runs it is covered by
 * {@link InvalidConfigurationFailsBuildTest}.
 */
public class HttpRateLimitBuildConfigValidatorTest {

    private static final String P = "quarkus.http.rate-limit.";
    private static final Set<String> STORES = Set.of("custom");
    private static final Set<String> KEY_RESOLVERS = Set.of("ip", "global", "principal", "tenant");
    private static final Set<String> OVERRIDES = Set.of("plans");

    /** A valid pre-authentication rule named {@code api} with the given overrides applied on top. */
    private static HttpRateLimitBuildTimeConfig config(String... overrides) {
        Map<String, String> values = new HashMap<>();
        values.put(P + "rules.api.paths", "/api/*");
        values.put(P + "rules.api.phase", "pre-authentication");
        values.put(P + "rules.api.request-key", "ip");
        for (int i = 0; i < overrides.length; i += 2) {
            if (overrides[i + 1] == null) {
                values.remove(overrides[i]);
            } else {
                values.put(overrides[i], overrides[i + 1]);
            }
        }
        return new SmallRyeConfigBuilder().addDefaultInterceptors().withMapping(HttpRateLimitBuildTimeConfig.class)
                .withDefaultValues(values).build().getConfigMapping(HttpRateLimitBuildTimeConfig.class);
    }

    private static List<String> validate(String... overrides) {
        return HttpRateLimitBuildConfigValidator.validate(config(overrides), STORES, KEY_RESOLVERS, OVERRIDES);
    }

    private static String g(String key) {
        return P + "rules.api." + key;
    }

    @Test
    void validConfigurationHasNoErrors() {
        assertThat(validate()).isEmpty();
    }

    @Test
    void postAuthenticationRuleIsValid() {
        assertThat(validate(g("phase"), "post-authentication", g("request-key"), "principal")).isEmpty();
    }

    @Test
    void principalRequestKeyNotAvailableBeforeAuthentication() {
        assertThat(validate(g("request-key"), "principal")).containsExactly(
                "Rate limit rule 'api' request-key 'principal' is not available before authentication; use phase=post-authentication");
    }

    @Test
    void phaseAndRequestKeyDefaultToTheGlobalOnes() {
        assertThat(validate(g("phase"), null, g("request-key"), null)).containsExactly(
                "Rate limit rule 'api' has no phase: set quarkus.http.rate-limit.rules.api.phase or quarkus.http.rate-limit.phase",
                "Rate limit rule 'api' has no request-key: set quarkus.http.rate-limit.rules.api.request-key or quarkus.http.rate-limit.request-key");
        assertThat(
                validate(g("phase"), null, g("request-key"), null, P + "phase", "pre-authentication", P + "request-key", "ip"))
                .isEmpty();
        // the global settings are checked like the rule ones
        assertThat(validate(g("phase"), null, g("request-key"), null, P + "phase", "pre-authentication", P + "request-key",
                "principal")).containsExactly(
                        "Rate limit rule 'api' request-key 'principal' is not available before authentication; use phase=post-authentication");
        // the rule settings win
        assertThat(validate(P + "phase", "post-authentication", P + "request-key", "principal")).isEmpty();
    }

    @Test
    void requestKeyMustMatchAResolver() {
        assertThat(validate(g("request-key"), "custom:unknown")).containsExactly(
                "Rate limit rule 'api' request-key 'custom:unknown' matches no RateLimitKeyResolver bean annotated @Identifier(\"unknown\")");
        assertThat(validate(g("request-key"), "custom:tenant")).isEmpty();
        assertThat(validate(g("request-key"), "header:X-Client")).isEmpty();
        // a bare name is a built-in key: an application's resolver has a namespace of its own, so that a later
        // built-in key cannot take its place
        assertThat(validate(g("request-key"), "tenant")).containsExactly(
                "Rate limit rule 'api' request-key 'tenant' is not a built-in key (ip, global, principal), header:<name> or custom:<identifier>; for the RateLimitKeyResolver bean annotated @Identifier(\"tenant\"), use custom:tenant");
        assertThat(validate(g("request-key"), "header:")).containsExactly(
                "Rate limit rule 'api' request-key 'header:' is not a built-in key (ip, global, principal), header:<name> or custom:<identifier>");
        assertThat(validate(g("request-key"), "custom:")).containsExactly(
                "Rate limit rule 'api' request-key 'custom:' is not a built-in key (ip, global, principal), header:<name> or custom:<identifier>");
    }

    @Test
    void headerNameMustBeAnHttpToken() {
        for (String name : List.of("X Tenant", "X:Tenant", "X/Tenant")) {
            assertThat(validate(g("request-key"), "header:" + name))
                    .containsExactly("quarkus.http.rate-limit.rules.api.request-key: header name '" + name
                            + "' is not an HTTP field name; use header:<name>, for example header:X-Tenant");
        }
        assertThat(validate(g("request-key"), "header:x-tenant_id")).isEmpty();
    }

    @Test
    void overrideMustExist() {
        String unknown = "Rate limit rule 'api' limit-resolver 'nope' matches no RateLimitResolver bean annotated @Identifier(\"nope\")";
        assertThat(validate(g("limit-resolver"), "nope")).containsExactly(unknown);
        assertThat(validate(P + "limit-resolver", "nope")).containsExactly(unknown);
        assertThat(validate(g("limit-resolver"), "plans")).isEmpty();
        assertThat(validate(P + "limit-resolver", "plans")).isEmpty();
        // the rule override wins over the global one
        assertThat(validate(P + "limit-resolver", "nope", g("limit-resolver"), "plans")).isEmpty();
    }

    @Test
    void storeMustExist() {
        String unknown = "Rate limit rule 'api' store 'nope' matches no RateLimitStore bean annotated @Identifier(\"nope\");"
                + " the built-in 'redis' store requires the quarkus-redis-client extension";
        assertThat(validate(g("store"), "nope")).containsExactly(unknown);
        assertThat(validate(P + "store", "nope")).containsExactly(unknown);
        assertThat(validate(g("store"), "custom")).isEmpty();
        assertThat(validate(P + "store", "custom")).isEmpty();
        // the rule store wins over the global one
        assertThat(validate(P + "store", "nope", g("store"), "local")).isEmpty();
    }

    @Test
    void wildcardMustBeWholeSegment() {
        assertThat(validate(g("paths"), "/api/v*/x")).containsExactly(
                "Rate limit rule 'api' path '/api/v*/x': a wildcard must be a whole path segment ('/a/*/b' or a trailing '/*'), not part of one");
        assertThat(validate(g("paths"), "/a/*/b,/a/*")).isEmpty();
    }

    @Test
    void methodMustBeToken() {
        assertThat(validate(g("methods"), "POST,BAD METHOD")).containsExactly(
                "Rate limit rule 'api' method 'BAD METHOD' is not an HTTP method token");
        assertThat(validate(g("methods"), "post,PATCH")).isEmpty();
    }

    /** The {@code api} rule with proactive authentication disabled, in an application without authentication annotations. */
    private static List<String> disabledProactiveAuth(String rootPath, String... overrides) {
        return HttpRateLimitBuildConfigValidator.validateAuthentication(config(overrides), false, rootPath, Set.of());
    }

    @Test
    void postAuthenticationRuleOnEveryPathNeedsProactiveAuthentication() {
        String error = "Rate limit rule 'api' has phase=post-authentication and matches every path, so it authenticates"
                + " every request and quarkus.http.auth.proactive=false has no effect. Set"
                + " quarkus.http.auth.proactive=true, or restrict the paths or methods of the rule.";
        String phase = g("phase");
        String paths = g("paths");
        assertThat(disabledProactiveAuth("/", phase, "post-authentication", paths, "/*")).containsExactly(error);
        // one such path is enough
        assertThat(disabledProactiveAuth("/", phase, "post-authentication", paths, "/api/*,/*")).containsExactly(error);
        // a path without a leading slash is relative to the root path
        assertThat(disabledProactiveAuth("/", phase, "post-authentication", paths, "*")).containsExactly(error);
        assertThat(disabledProactiveAuth("/app", phase, "post-authentication", paths, "*")).containsExactly(error);
        // every path under the root path
        assertThat(disabledProactiveAuth("/app", phase, "post-authentication", paths, "/app/*")).containsExactly(error);
        assertThat(disabledProactiveAuth("/app/", phase, "post-authentication", paths, "/app/*")).containsExactly(error);
        assertThat(disabledProactiveAuth("/app", phase, "post-authentication", paths, "/*")).containsExactly(error);
        // the phase may be the global one
        assertThat(disabledProactiveAuth("/", phase, null, P + "phase", "post-authentication", paths, "/*"))
                .containsExactly(error);

        // proactive authentication authenticates every request anyway
        assertThat(HttpRateLimitBuildConfigValidator.validateAuthentication(
                config(phase, "post-authentication", paths, "/*"), true, "/", Set.of())).isEmpty();
        // the requests to other paths are still authenticated only when something asks for the identity
        assertThat(disabledProactiveAuth("/", phase, "post-authentication")).isEmpty();
        assertThat(disabledProactiveAuth("/", phase, "post-authentication", paths, "/*/items")).isEmpty();
        assertThat(disabledProactiveAuth("/app", phase, "post-authentication", paths, "/app/api/*")).isEmpty();
        // and so are the requests with other methods
        assertThat(disabledProactiveAuth("/", phase, "post-authentication", paths, "/*", g("methods"), "POST")).isEmpty();
        // a pre-authentication rule authenticates nothing
        assertThat(disabledProactiveAuth("/", paths, "/*")).isEmpty();
    }

    @Test
    void postAuthenticationRuleExcludesAuthenticationAnnotations() {
        String phase = g("phase");
        Set<String> annotated = Set.of("org.acme.AdminResource#list");
        assertThat(HttpRateLimitBuildConfigValidator.validateAuthentication(config(phase, "post-authentication"), false,
                "/", annotated)).containsExactly("Rate limit rule 'api' has phase=post-authentication, but the application"
                        + " uses annotations such as @BasicAuthentication or @Tenant (found on"
                        + " org.acme.AdminResource#list). These annotations can select the authentication mechanism or"
                        + " resolve the OIDC tenant only after the endpoint has been matched, and the rule authenticates"
                        + " the request before that. Use phase=pre-authentication, or select the authentication"
                        + " mechanism or the tenant by path.");
        // the first three endpoints in alphabetical order
        assertThat(HttpRateLimitBuildConfigValidator.validateAuthentication(config(phase, "post-authentication"), false,
                "/", Set.of("org.acme.D", "org.acme.B#b", "org.acme.E#e", "org.acme.A#a", "org.acme.C")))
                .singleElement().asString().contains("(found on org.acme.A#a, org.acme.B#b, org.acme.C and 2 more)");
        // a rule on every path fails for the annotations only, because they do not allow proactive authentication
        assertThat(HttpRateLimitBuildConfigValidator.validateAuthentication(
                config(phase, "post-authentication", g("paths"), "/*"), false, "/", annotated))
                .singleElement().asString().contains("uses annotations such as");
        // the phase may be the global one
        assertThat(HttpRateLimitBuildConfigValidator.validateAuthentication(
                config(phase, null, P + "phase", "post-authentication"), false, "/", annotated))
                .singleElement().asString().contains("uses annotations such as");

        // a pre-authentication rule authenticates nothing
        assertThat(HttpRateLimitBuildConfigValidator.validateAuthentication(config(), false, "/", annotated)).isEmpty();
        // the annotations select the authentication of an endpoint only when proactive authentication is disabled
        assertThat(HttpRateLimitBuildConfigValidator.validateAuthentication(config(phase, "post-authentication"), true,
                "/", annotated)).isEmpty();
        // no annotation
        assertThat(HttpRateLimitBuildConfigValidator.validateAuthentication(config(phase, "post-authentication"), false,
                "/", Set.of())).isEmpty();
    }

}
