package io.quarkus.spiffe.client.runtime.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class SpiffeEndpointParsingTest {

    @Test
    void validUnixEndpoint() {
        SpiffeClientBuilder builder = new SpiffeClientBuilder()
                .endpointSocket("unix:///run/spire/agent.sock");
        assertThat(builder.build()).isNull();
    }

    @Test
    void validTcpEndpoint() {
        SpiffeClientBuilder builder = new SpiffeClientBuilder()
                .endpointSocket("tcp://127.0.0.1:8080");
        assertThat(builder.build()).isNull();
    }

    @Test
    void emptyEndpointThrows() {
        assertThatThrownBy(() -> new SpiffeClientBuilder()
                .endpointSocket("")
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void noSchemeThrows() {
        assertThatThrownBy(() -> new SpiffeClientBuilder()
                .endpointSocket("blah")
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void unixWithAuthorityThrows() {
        assertThatThrownBy(() -> new SpiffeClientBuilder()
                .endpointSocket("unix://authority/path")
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void unixBlankPathThrows() {
        assertThatThrownBy(() -> new SpiffeClientBuilder()
                .endpointSocket("unix:///")
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void unixOpaqueThrows() {
        assertThatThrownBy(() -> new SpiffeClientBuilder()
                .endpointSocket("unix:opaque")
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void unixWithQueryThrows() {
        assertThatThrownBy(() -> new SpiffeClientBuilder()
                .endpointSocket("unix:///foo?query=1")
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void unixWithFragmentThrows() {
        assertThatThrownBy(() -> new SpiffeClientBuilder()
                .endpointSocket("unix:///foo#fragment")
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void tcpWithHostnameThrows() {
        assertThatThrownBy(() -> new SpiffeClientBuilder()
                .endpointSocket("tcp://hostname:8080")
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void tcpNoPortThrows() {
        assertThatThrownBy(() -> new SpiffeClientBuilder()
                .endpointSocket("tcp://127.0.0.1")
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void tcpNoHostThrows() {
        assertThatThrownBy(() -> new SpiffeClientBuilder()
                .endpointSocket("tcp:///path")
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void tcpWithPathThrows() {
        assertThatThrownBy(() -> new SpiffeClientBuilder()
                .endpointSocket("tcp://127.0.0.1:8080/path")
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void tcpWithQueryThrows() {
        assertThatThrownBy(() -> new SpiffeClientBuilder()
                .endpointSocket("tcp://127.0.0.1:8080?q=1")
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void tcpWithFragmentThrows() {
        assertThatThrownBy(() -> new SpiffeClientBuilder()
                .endpointSocket("tcp://127.0.0.1:8080#frag")
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void tcpWithUserinfoThrows() {
        assertThatThrownBy(() -> new SpiffeClientBuilder()
                .endpointSocket("tcp://user:pass@127.0.0.1:8080")
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void unknownSchemeThrows() {
        assertThatThrownBy(() -> new SpiffeClientBuilder()
                .endpointSocket("http://127.0.0.1:8080")
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void validUnixShortForm() {
        SpiffeClientBuilder builder = new SpiffeClientBuilder()
                .endpointSocket("unix:/run/spire/agent.sock");
        assertThat(builder.build()).isNull();
    }

    @Test
    void unixRootPathOnlyThrows() {
        assertThatThrownBy(() -> new SpiffeClientBuilder()
                .endpointSocket("unix:/")
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void tcpOpaqueThrows() {
        assertThatThrownBy(() -> new SpiffeClientBuilder()
                .endpointSocket("tcp:opaque")
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void nullEndpointThrows() {
        assertThatThrownBy(() -> new SpiffeClientBuilder()
                .endpointSocket(null)
                .build())
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void tcpEmptyAuthorityThrows() {
        assertThatThrownBy(() -> new SpiffeClientBuilder()
                .endpointSocket("tcp://")
                .build())
                .isInstanceOf(IllegalArgumentException.class);
    }
}
