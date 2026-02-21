package io.quarkus.email.authentication.runtime.internal;

import java.util.Set;

import jakarta.enterprise.context.ApplicationScoped;

import io.quarkus.arc.DefaultBean;
import io.quarkus.email.authentication.EmailAuthenticationTokenSender;
import io.quarkus.mailer.Mail;
import io.quarkus.mailer.reactive.ReactiveMailer;
import io.quarkus.mailer.runtime.Mailers;
import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.security.AuthenticationFailedException;
import io.quarkus.security.identity.SecurityIdentity;
import io.smallrye.mutiny.Uni;

@DefaultBean
@ApplicationScoped
class DefaultEmailAuthenticationTokenSender implements EmailAuthenticationTokenSender {

    /**
     * The {@link io.quarkus.security.identity.SecurityIdentity#getAttribute(String)} key for the email address.
     */
    private static final String EMAIL_ATTRIBUTE_KEY = "email";

    private final ReactiveMailer mailer;
    private final String emailSubject;
    private final String emailText;

    DefaultEmailAuthenticationTokenSender(Mailers mailers, EmailAuthenticationConfig config) {
        this.mailer = getReactiveMailer(mailers, config);
        this.emailSubject = config.emailSubject();
        this.emailText = getEmailText(config);
    }

    @Override
    public Uni<Void> sendToken(char[] token, SecurityIdentity securityIdentity) {
        String emailAddress = securityIdentity.getAttribute(EMAIL_ATTRIBUTE_KEY);
        if (emailAddress == null || emailAddress.isEmpty()) {
            return Uni.createFrom().failure(new AuthenticationFailedException(
                    "SecurityIdentity must have attribute '%s' with email address".formatted(EMAIL_ATTRIBUTE_KEY)));
        }
        return mailer.send(createEmail(token, emailAddress));
    }

    private Mail createEmail(char[] token, String email) {
        return Mail.withText(email, emailSubject, emailText.formatted(new String(token)));
    }

    private static ReactiveMailer getReactiveMailer(Mailers mailers, EmailAuthenticationConfig config) {
        ReactiveMailer reactiveMailer = mailers.reactiveMailerFromName(config.mailerName());
        if (reactiveMailer == null) {
            throw new ConfigurationException(
                    "Cannot find '%s' with name '%s'.".formatted(ReactiveMailer.class.getName(), config.mailerName()),
                    Set.of("quarkus.email-authentication.mailer-name"));
        }
        return reactiveMailer;
    }

    private static String getEmailText(EmailAuthenticationConfig config) {
        if (!config.emailText().contains("%s")) {
            throw new ConfigurationException("Email text must contain '%s' marking the position of email authentication token",
                    Set.of("quarkus.email-authentication.email-text"));
        }
        return config.emailText();
    }
}
