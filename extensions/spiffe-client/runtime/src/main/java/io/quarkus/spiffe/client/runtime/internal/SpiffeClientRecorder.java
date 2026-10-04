package io.quarkus.spiffe.client.runtime.internal;

import static io.quarkus.runtime.configuration.DurationConverter.parseDuration;

import java.util.function.Supplier;

import io.quarkus.runtime.annotations.Recorder;
import io.quarkus.tls.TlsConfiguration;

@Recorder
public class SpiffeClientRecorder {

    public Supplier<TlsConfiguration> createSpiffeTlsConfiguration(String tlsConfigurationName, String spiffeId,
            String reloadPeriod) {
        return () -> new SpiffeTlsConfiguration(tlsConfigurationName, parseDuration(reloadPeriod), spiffeId);
    }

}
