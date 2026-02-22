package io.quarkus.email.authentication.runtime.internal;

import java.util.Set;

import io.quarkus.arc.DefaultBean;
import io.quarkus.email.authentication.EmailAuthenticationTokenSender;
import io.quarkus.mailer.Mail;
import io.quarkus.mailer.reactive.ReactiveMailer;
import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.security.identity.SecurityIdentity;
import io.smallrye.mutiny.Uni;
import io.vertx.ext.mail.mailencoder.EmailAddress;

@DefaultBean
class DefaultEmailAuthenticationTokenSender implements EmailAuthenticationTokenSender {

    private final ReactiveMailer mailer;
    private final String emailSubject;
    private final String emailText;

    DefaultEmailAuthenticationTokenSender(ReactiveMailer mailer, EmailAuthenticationConfig config) {
        this.mailer = mailer;
        this.emailSubject = config.emailSubject();
        this.emailText = getEmailText(config);
    }

    @Override
    public Uni<Void> sendToken(char[] token, SecurityIdentity securityIdentity) {
        String emailAddress = securityIdentity.getAttribute(EMAIL);
        if (emailAddress == null) {
            emailAddress = securityIdentity.getPrincipal().getName();
            if (isNotValidEmailAddress(emailAddress)) {
                return Uni.createFrom().failure(new IllegalArgumentException(("SecurityIdentity must have attribute '%s'"
                        + " with email address or its principal name '%s' must be a valid email address")
                        .formatted(EMAIL, emailAddress)));
            }
        } else if (isNotValidEmailAddress(emailAddress)) {
            return Uni.createFrom().failure(new IllegalArgumentException(("SecurityIdentity attribute '%s' value '%s' "
                    + "is not valid email address").formatted(EMAIL, emailAddress)));
        }
        return mailer.send(createEmail(token, emailAddress));
    }

    private Mail createEmail(char[] token, String email) {
        return Mail.withText(email, emailSubject, emailText.formatted(new String(token)));
    }

    private static String getEmailText(EmailAuthenticationConfig config) {
        if (!config.emailText().contains("%s")) {
            throw new ConfigurationException("Email text must contain '%s' marking the position of email authentication token",
                    Set.of("quarkus.email-authentication.email-text"));
        }
        return config.emailText();
    }

    private static boolean isNotValidEmailAddress(String maybeEmail) {
        try {
            new EmailAddress(maybeEmail); // just here to validate the email address
            return false;
        } catch (Exception e) {
            return true;
        }
    }
}
