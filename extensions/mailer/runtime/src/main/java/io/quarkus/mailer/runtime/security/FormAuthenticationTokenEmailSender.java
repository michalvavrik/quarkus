package io.quarkus.mailer.runtime.security;

import jakarta.enterprise.context.ApplicationScoped;

import io.quarkus.arc.Unremovable;
import io.quarkus.mailer.Mail;
import io.quarkus.mailer.reactive.ReactiveMailer;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.spi.runtime.FormAuthenticationTokenSender;
import io.smallrye.mutiny.Uni;

@Unremovable
@ApplicationScoped // TODO: register as CDI bean if: email-based auth mech enabled (mailer property), security & vertx-http present
public class FormAuthenticationTokenEmailSender implements FormAuthenticationTokenSender {

    private final ReactiveMailer mailer;
    private final String emailSubject;
    private final String emailText;
    private final String identityEmailAttributeKey;

    FormAuthenticationTokenEmailSender(ReactiveMailer mailer) {
        // TODO: make "email attribute on security identity", "email subject", "email text" configurable
        this.mailer = mailer;
        this.identityEmailAttributeKey = "email";
        this.emailSubject = "Your [Company Name] verification code"; // TODO: validate not empty
        this.emailText = "Your security code is %s"; // TODO: validate that it contains one %s
    }

    @Override
    public Uni<Void> sendToken(char[] token, SecurityIdentity securityIdentity) {
        String emailAddress = securityIdentity.getAttribute(identityEmailAttributeKey);
        if (emailAddress == null || emailAddress.isBlank()) {
            return Uni.createFrom().failure(new IllegalArgumentException(
                    "SecurityIdentity must have attribute '" + identityEmailAttributeKey + "' with email address"));
        }

        return mailer.send(createEmail(token, emailAddress));
    }

    private Mail createEmail(char[] token, String to) {
        return Mail.withText(to, emailSubject, emailText.formatted(new String(token)));
    }
}
