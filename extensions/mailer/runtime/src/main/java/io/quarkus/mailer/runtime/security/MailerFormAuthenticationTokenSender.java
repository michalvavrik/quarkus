package io.quarkus.mailer.runtime.security;

import java.util.Objects;
import java.util.Set;

import io.quarkus.mailer.Mail;
import io.quarkus.mailer.reactive.ReactiveMailer;
import io.quarkus.mailer.runtime.Mailers;
import io.quarkus.mailer.runtime.MailersRuntimeConfig;
import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.security.spi.runtime.FormAuthenticationTokenSender;
import io.smallrye.mutiny.Uni;

/**
 * Form authentication token sender, which uses a reactive mailer to send tokens.
 */
public class MailerFormAuthenticationTokenSender implements FormAuthenticationTokenSender {

    private final ReactiveMailer mailer;
    private final String emailSubject;
    private final String emailText;

    MailerFormAuthenticationTokenSender(Mailers mailers, MailersRuntimeConfig config) {
        this.mailer = getReactiveMailer(mailers, config.formTokenSender());
        this.emailSubject = getEmailSubject(config.formTokenSender());
        this.emailText = getEmailText(config.formTokenSender());
    }

    @Override
    public Uni<Void> sendToken(char[] token, String email) {
        return mailer.send(createEmail(token, email));
    }

    private Mail createEmail(char[] token, String email) {
        return Mail.withText(email, emailSubject, emailText.formatted(new String(token)));
    }

    private static ReactiveMailer getReactiveMailer(Mailers mailers, MailerFormAuthenticationTokenConfig config) {
        return Objects.requireNonNull(mailers.reactiveMailerFromName(config.mailerName()), () -> """
                Cannot find 'io.quarkus.mailer.reactive.ReactiveMailer' with name '%s'.
                Please configure correct name with the 'quarkus.mailer.form-token-sender.mailer-name' configuration property.
                """.formatted(config.mailerName()));
    }

    private static String getEmailText(MailerFormAuthenticationTokenConfig config) {
        if (!config.text().contains("%s")) {
            throw new ConfigurationException("Email text must contain '%s' marking the position of form authentication token",
                    Set.of("quarkus.mailer.form-token-sender.subject"));
        }
        return config.text();
    }

    private static String getEmailSubject(MailerFormAuthenticationTokenConfig config) {
        if (config.subject().isBlank()) {
            throw new ConfigurationException("Email subject must not be blank",
                    Set.of("quarkus.mailer.form-token-sender.subject"));
        }
        return config.subject();
    }
}
