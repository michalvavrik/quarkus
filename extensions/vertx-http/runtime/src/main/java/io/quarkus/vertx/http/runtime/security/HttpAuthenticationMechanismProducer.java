package io.quarkus.vertx.http.runtime.security;

import java.security.SecureRandom;
import java.util.Base64;

import jakarta.enterprise.inject.Produces;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.jboss.logging.Logger;

import io.quarkus.arc.lookup.LookupIfProperty;
import io.quarkus.arc.lookup.LookupUnlessProperty;
import io.quarkus.vertx.http.runtime.FormAuthConfig;
import io.quarkus.vertx.http.runtime.HttpConfiguration;

@Singleton
public class HttpAuthenticationMechanismProducer {

    private static final Logger LOG = Logger.getLogger(HttpAuthenticationMechanismProducer.class);

    //the temp encryption key, persistent across dev mode restarts
    private static volatile String encryptionKey;

    @Inject
    HttpConfiguration httpConfiguration;

    @LookupIfProperty(name = "quarkus.http.auth.form.enabled", stringValue = "true")
    @Singleton
    @Produces
    FormAuthenticationMechanism formAuthenticationMechanism() {
        final String key;
        if (httpConfiguration.encryptionKey.isEmpty()) {
            if (encryptionKey != null) {
                //persist across dev mode restarts
                key = encryptionKey;
            } else {
                byte[] data = new byte[32];
                new SecureRandom().nextBytes(data);
                key = encryptionKey = Base64.getEncoder().encodeToString(data);
                LOG.warn("Encryption key was not specified for persistent FORM auth, using temporary key " + key);
            }
        } else {
            key = httpConfiguration.encryptionKey.get();
        }
        FormAuthConfig form = httpConfiguration.auth.form;
        PersistentLoginManager loginManager = new PersistentLoginManager(key, form.cookieName, form.timeout.toMillis(),
                form.newCookieInterval.toMillis(), form.httpOnlyCookie, form.cookieSameSite.name(),
                form.cookiePath.orElse(null));
        String loginPage = startWithSlash(form.loginPage.orElse(null));
        String errorPage = startWithSlash(form.errorPage.orElse(null));
        String landingPage = startWithSlash(form.landingPage.orElse(null));
        String postLocation = startWithSlash(form.postLocation);
        String usernameParameter = form.usernameParameter;
        String passwordParameter = form.passwordParameter;
        String locationCookie = form.locationCookie;
        String cookiePath = form.cookiePath.orElse(null);
        boolean redirectAfterLogin = form.redirectAfterLogin;
        return new FormAuthenticationMechanism(loginPage, postLocation, usernameParameter, passwordParameter,
                errorPage, landingPage, redirectAfterLogin, locationCookie, form.cookieSameSite.name(), cookiePath,
                loginManager);
    }

    @LookupUnlessProperty(name = "quarkus.http.ssl.client-auth", stringValue = "NONE")
    @Produces
    @Singleton
    MtlsAuthenticationMechanism mtlsAuthenticationMechanism() {
        return new MtlsAuthenticationMechanism();
    }

    //basic auth explicitly enabled
    @LookupIfProperty(name = "quarkus.http.auth.basic", stringValue = "true")
    @Produces
    @Singleton
    BasicAuthenticationMechanism basicAuthenticationMechanism() {
        return createBasicAuthMechanism();
    }

    //basic auth not explicitly disabled
    @LookupUnlessProperty(name = "quarkus.http.auth.basic", stringValue = "false", lookupIfMissing = true)
    //basic auth not explicitly enabled
    @LookupUnlessProperty(name = "quarkus.http.auth.basic", stringValue = "true", lookupIfMissing = true)
    // form auth not enabled
    @LookupUnlessProperty(name = "quarkus.http.auth.form.enabled", stringValue = "true", lookupIfMissing = true)
    // mTLS auth not enabled
    @LookupIfProperty(name = "quarkus.http.ssl.client-auth", stringValue = "NONE", lookupIfMissing = true)
    @Produces
    @Singleton
    BasicAuthenticationMechanism fallbackIfNoOtherAuthMechanismIsAvailable() {
        // ideally this should be @DefaultBean, but that leaves this bean
        // always removed as we already define beans 'MtlsAuthenticationMechanism',
        // 'FormAuthenticationMechanism' and 'BasicAuthenticationMechanism' and
        // they are only removed from lookup
        return createBasicAuthMechanism();
    }

    private BasicAuthenticationMechanism createBasicAuthMechanism() {
        return new BasicAuthenticationMechanism(httpConfiguration.auth.realm.orElse(null),
                httpConfiguration.auth.form.enabled);
    }

    private static String startWithSlash(String page) {
        if (page == null) {
            return null;
        }
        return page.startsWith("/") ? page : "/" + page;
    }
}
