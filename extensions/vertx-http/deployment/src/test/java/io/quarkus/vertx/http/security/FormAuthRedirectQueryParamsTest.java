package io.quarkus.vertx.http.security;

import static io.restassured.matcher.RestAssuredMatchers.detailedCookie;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.notNullValue;

import java.time.Duration;
import java.util.Set;

import jakarta.enterprise.event.Observes;

import org.hamcrest.Matcher;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.security.identity.IdentityProviderManager;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.AuthenticationRequest;
import io.quarkus.security.test.utils.TestIdentityController;
import io.quarkus.security.test.utils.TestIdentityProvider;
import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.vertx.http.runtime.FormAuthConfig.CookieSameSite;
import io.quarkus.vertx.http.runtime.security.ChallengeData;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.quarkus.vertx.http.runtime.security.HttpCredentialTransport;
import io.restassured.RestAssured;
import io.restassured.filter.cookie.CookieFilter;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.web.RoutingContext;

class FormAuthRedirectQueryParamsTest {

    @RegisterExtension
    static final QuarkusUnitTest test = new QuarkusUnitTest().withApplicationRoot(jar -> jar
            .addClasses(TestIdentityProvider.class, TestIdentityController.class, TestTrustedIdentityProvider.class,
                    PathHandler.class, HttpSecurityConfigurator.class, DelegatingMechanism.class));

    @BeforeAll
    static void setup() {
        TestIdentityController.resetRoles()
                .add("admin", "admin", "admin");
        RestAssured.enableLoggingOfRequestAndResponseIfValidationFails();
    }

    @Test
    void testSingleQueryParamPassed() {
        testLoginPageQueryParams("/admin", Set.of("jfwid=1234"), Set.of(), Set.of());
        testLandingPageQueryParams(Set.of("jfwid=1234"), Set.of(), Set.of());
        testErrorPageQueryParams(Set.of("jfwid=1234"), Set.of(), Set.of());
    }

    private static void testErrorPageQueryParams(Set<String> queryParams, Set<String> passedQueryParams,
            Set<String> ignoredQueryParams) {
        var passedParamsMatcher = getPassedParamsMatcher(passedQueryParams);

        RestAssured
                .given()
                .redirects().follow(false)
                .when()
                .formParam("j_username", "admin")
                .formParam("j_password", "wrong")
                .post("/j_security_check?" + String.join("&", queryParams))
                .then()
                .assertThat()
                .statusCode(302)
                .header("location", containsString("/error"))
                .header("location", passedParamsMatcher)
                .header("location", getIgnoredParamsMatcher(ignoredQueryParams));
    }

    private static void testLandingPageQueryParams(Set<String> queryParams, Set<String> passedQueryParams,
            Set<String> ignoredQueryParams) {
        var passedParamsMatcher = getPassedParamsMatcher(passedQueryParams);

        RestAssured
                .given()
                .redirects().follow(false)
                .when()
                .formParam("j_username", "admin")
                .formParam("j_password", "admin")
                .post("/j_security_check?" + String.join("&", queryParams))
                .then()
                .assertThat()
                .statusCode(302)
                .header("location", containsString("/landing"))
                .header("location", passedParamsMatcher)
                .header("location", getIgnoredParamsMatcher(ignoredQueryParams))
                .cookie("laitnederc-sukrauq", detailedCookie().value(notNullValue())
                        .httpOnly(true).sameSite("Lax").maxAge(120));
    }

    private static void testLoginPageQueryParams(String path, Set<String> queryParams, Set<String> passedQueryParams,
            Set<String> ignoredQueryParams) {
        CookieFilter cookies = new CookieFilter();
        String queryParamsString = String.join("&", queryParams);
        var passedParamsMatcher = getPassedParamsMatcher(passedQueryParams);
        RestAssured
                .given()
                .filter(cookies)
                .redirects().follow(false)
                .when()
                .get(path + "?" + queryParamsString)
                .then()
                .assertThat()
                .statusCode(302)
                .header("location", containsString("/login"))
                .header("location", passedParamsMatcher)
                .header("location", getIgnoredParamsMatcher(ignoredQueryParams))
                .cookie("quarkus-redirect-location",
                        detailedCookie().value(allOf(containsString(path), passedParamsMatcher)).sameSite("Lax"));

        RestAssured
                .given()
                .filter(cookies)
                .redirects().follow(false)
                .when()
                .formParam("j_username", "admin")
                .formParam("j_password", "admin")
                .post("/j_security_check")
                .then()
                .assertThat()
                .statusCode(302)
                .header("location", allOf(containsString(path), passedParamsMatcher))
                .cookie("laitnederc-sukrauq", detailedCookie().value(notNullValue())
                        .httpOnly(true).sameSite("Lax").maxAge(120));

        RestAssured
                .given()
                .filter(cookies)
                .redirects().follow(false)
                .when()
                .get(path + "?" + queryParamsString)
                .then()
                .assertThat()
                .statusCode(200)
                .body(equalTo("admin:" + path));
    }

    private static Matcher<String> getIgnoredParamsMatcher(Set<String> ignoredQueryParams) {
        return ignoredQueryParams.stream().map(Matchers::containsString).map(Matchers::not).reduce(Matchers::allOf)
                .orElse(Matchers.containsString(""));
    }

    private static Matcher<String> getPassedParamsMatcher(Set<String> passedQueryParams) {
        return passedQueryParams.stream().map(Matchers::containsString).reduce(Matchers::allOf)
                .orElse(Matchers.containsString(""));
    }

    static class HttpSecurityConfigurator {

        void configureHttpPermission(@Observes HttpSecurity httpSecurity) {
            httpSecurity.path("/admin").roles("admin");
        }

        void configureFormAuthentication(@Observes HttpSecurity httpSecurity) {
            var singleQueryParam = createFormBuilderBase().build();
            var multipleQueryParams = new DelegatingMechanism(createFormBuilderBase().build(), "multiple-query-param");
            var noQueryParams = new DelegatingMechanism(createFormBuilderBase().build(), "no-query-param");
            httpSecurity.mechanism(singleQueryParam);
        }

        private static Form.Builder createFormBuilderBase() {
            return Form.builder()
                    .loginPage("login")
                    .errorPage("error")
                    .landingPage("landing")
                    .timeout(Duration.ofSeconds(2))
                    .newCookieInterval(Duration.ofSeconds(1))
                    .cookieName("laitnederc-sukrauq")
                    .cookieSameSite(CookieSameSite.LAX)
                    .httpOnlyCookie()
                    .cookieMaxAge(Duration.ofMinutes(2))
                    .encryptionKey("CHANGEIT-CHANGEIT-CHANGEIT-CHANGEIT-CHANGEIT");
        }
    }

    private static final class DelegatingMechanism implements HttpAuthenticationMechanism {

        private final HttpAuthenticationMechanism delegate;
        private final String name;

        private DelegatingMechanism(HttpAuthenticationMechanism httpAuthenticationMechanism, String name) {
            this.delegate = httpAuthenticationMechanism;
            this.name = name;
        }

        @Override
        public Uni<SecurityIdentity> authenticate(RoutingContext context, IdentityProviderManager identityProviderManager) {
            return delegate.authenticate(context, identityProviderManager);
        }

        @Override
        public Uni<ChallengeData> getChallenge(RoutingContext context) {
            return delegate.getChallenge(context);
        }

        @Override
        public Set<Class<? extends AuthenticationRequest>> getCredentialTypes() {
            return delegate.getCredentialTypes();
        }

        @Override
        public Uni<Boolean> sendChallenge(RoutingContext context) {
            return delegate.sendChallenge(context);
        }

        @Override
        public Uni<HttpCredentialTransport> getCredentialTransport(RoutingContext context) {
            return Uni.createFrom()
                    .item(new HttpCredentialTransport(HttpCredentialTransport.Type.POST, "/j_security_check", name));
        }

        @Override
        public int getPriority() {
            return delegate.getPriority();
        }
    }
}
