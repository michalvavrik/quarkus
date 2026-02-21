package io.quarkus.email.authentication.runtime.internal;

import java.time.Duration;
import java.util.Optional;

import io.quarkus.email.authentication.EmailAuthenticationTokenStorage.DefaultEmailAuthenticationTokenStorage;
import io.quarkus.mailer.runtime.Mailers;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanism;
import io.smallrye.config.ConfigMapping;
import io.smallrye.config.WithDefault;

/**
 * Email authentication configuration.
 */
@ConfigMapping(prefix = "quarkus.email-authentication")
interface EmailAuthenticationConfig {

    /**
     * SameSite attribute values for the session, location and token cookies.
     */
    enum CookieSameSite {
        STRICT,
        LAX,
        NONE
    }

    /**
     * The login page. Redirect to login page can be disabled by setting `quarkus.email-authentication.login-page=`.
     */
    @WithDefault("/login.html")
    Optional<String> loginPage();

    /**
     * The username name field.
     */
    @WithDefault("j_username")
    String usernameParameter();

    /**
     * The error page. Redirect to error page can be disabled by setting `quarkus.email-authentication.error-page=`.
     */
    @WithDefault("/error.html")
    Optional<String> errorPage();

    /**
     * The landing page to redirect to if there is no saved page to redirect back to.
     * Redirect to landing page can be disabled by setting `quarkus.email-authentication.landing-page=`.
     */
    @WithDefault("/index.html")
    Optional<String> landingPage();

    /**
     * Option to control the name of the cookie used to redirect the user back to the location they want to access.
     */
    @WithDefault("quarkus-redirect-location")
    String locationCookie();

    /**
     * The inactivity (idle) timeout
     * <p>
     * When inactivity timeout is reached, cookie is not renewed and a new login is enforced.
     */
    @WithDefault("30M")
    Duration timeout();

    /**
     * How old a session cookie can get before it will be replaced with a new cookie with an updated timeout, also
     * referred to as "renewal-timeout".
     * <p>
     * Note that smaller values will result in slightly more server load (as new encrypted cookies will be
     * generated more often); however, larger values affect the inactivity timeout because the timeout is set
     * when a cookie is generated.
     * <p>
     * For example if this is set to 10 minutes, and the inactivity timeout is 30m, if a user's last request
     * is when the cookie is 9m old then the actual timeout will happen 21m after the last request because the timeout
     * is only refreshed when a new cookie is generated.
     * <p>
     * That is, no timeout is tracked on the server side; the timestamp is encoded and encrypted in the cookie
     * itself, and it is decrypted and parsed with each request.
     */
    @WithDefault("1M")
    Duration newSessionCookieInterval();

    /**
     * The cookie that is used to store the persistent session.
     */
    @WithDefault("quarkus-credential")
    String sessionCookie();

    /**
     * The cookie path for the session, location and token cookies.
     */
    @WithDefault("/")
    Optional<String> cookiePath();

    /**
     * Cookie domain parameter value which, if set, will be used for the session, location and token cookies.
     */
    Optional<String> cookieDomain();

    /**
     * Set the HttpOnly attribute to prevent access to the cookies via JavaScript.
     */
    @WithDefault("true")
    boolean httpOnlyCookie();

    /**
     * SameSite attribute for the session, location and token cookies.
     */
    @WithDefault("strict")
    CookieSameSite cookieSameSite();

    /**
     * Max-Age attribute for the session cookie. This is the amount of time the browser will keep the cookie.
     * <p>
     * The default value is empty, which means the cookie will be kept until the browser is closed.
     */
    Optional<Duration> sessionCookieMaxAge();

    /**
     * Path of the page where email authentication token should be submitted in order to receive credentials
     * (session cookie). The token should be submitted as form parameter with name {@link #tokenParameter()}
     * and using the HTTP method POST.
     */
    @WithDefault("/j_security_check")
    String postLocation();

    /**
     * Email authentication mechanism priority.
     *
     * @see HttpAuthenticationMechanism#getPriority()
     */
    @WithDefault(HttpAuthenticationMechanism.DEFAULT_PRIORITY + "")
    int priority();

    /**
     * Path of the page where users should be redirected when the token was generated and sent.
     * Redirect to this page can be disabled by setting `quarkus.email-authentication.token-page=`.
     */
    @WithDefault("/token.html")
    Optional<String> tokenPage();

    /**
     * The token field name.
     */
    @WithDefault("j_token")
    String tokenParameter();

    /**
     * The generated token length.
     */
    @WithDefault("15")
    int tokenLength();

    /**
     * Path of the page where {@link #usernameParameter()} should be submitted using POST method in order
     * to request email authentication token.
     */
    @WithDefault("/generate-email-authentication-token")
    String tokenGenerationLocation();

    /**
     * The email authentication token expiration time used by the {@link DefaultEmailAuthenticationTokenStorage}.
     */
    @WithDefault("5M")
    Duration tokenExpiresIn();

    /**
     * The name of the cookie used to store the token request by the {@link DefaultEmailAuthenticationTokenStorage}.
     */
    @WithDefault("quarkus-credential-request")
    String tokenCookie();

    /**
     * Name of the mailer used to send form authentication tokens.
     * This configuration property is used by the default {@link io.quarkus.email.authentication.EmailAuthenticationTokenSender}
     * implementation.
     */
    @WithDefault(Mailers.DEFAULT_MAILER_NAME)
    String mailerName();

    /**
     * Subject of the email carrying the email authentication token.
     * This configuration property is used by the default {@link io.quarkus.email.authentication.EmailAuthenticationTokenSender}
     * implementation.
     */
    @WithDefault("Your verification code")
    String emailSubject();

    /**
     * Text of the email carrying the email authentication token.
     * The text must contain '%s', marking the position of the token.
     * This configuration property is used by the default {@link io.quarkus.email.authentication.EmailAuthenticationTokenSender}
     * implementation.
     */
    @WithDefault("Your verification code is %s")
    String emailText();
}
