package io.quarkus.spiffe.client.runtime.internal;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Set;

import org.junit.jupiter.api.Test;

import io.quarkus.spiffe.client.api.JwtSvidRequest;

class JwtSvidRequestTest {

    @Test
    void nullAudienceThrows() {
        assertThatThrownBy(() -> JwtSvidRequest.forAudience((String[]) null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void blankAudienceThrows() {
        assertThatThrownBy(() -> JwtSvidRequest.forAudience("  "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void emptyAudiencesThrows() {
        assertThatThrownBy(() -> JwtSvidRequest.forAudience(new String[0]))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void buildWithoutAudienceThrows() {
        assertThatThrownBy(() -> JwtSvidRequest.builder().build())
                .isInstanceOf(IllegalStateException.class);
    }

    @Test
    void nullSpiffeIdThrows() {
        assertThatThrownBy(() -> JwtSvidRequest.builder().spiffeId(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void blankSpiffeIdThrows() {
        assertThatThrownBy(() -> JwtSvidRequest.builder().spiffeId("  "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void singleAudience() {
        JwtSvidRequest request = JwtSvidRequest.forAudience("spiffe://test.quarkus.io/resource-server");

        assertThat(request.audiences()).containsExactly("spiffe://test.quarkus.io/resource-server");
        assertThat(request.spiffeId()).isNull();
    }

    @Test
    void multipleAudiences() {
        JwtSvidRequest request = JwtSvidRequest.forAudience(
                "spiffe://test.quarkus.io/resource-server",
                "spiffe://test.quarkus.io/api-gateway");

        assertThat(request.audiences()).containsExactlyInAnyOrder(
                "spiffe://test.quarkus.io/resource-server",
                "spiffe://test.quarkus.io/api-gateway");
    }

    @Test
    void builderWithSpiffeId() {
        JwtSvidRequest request = JwtSvidRequest.builder()
                .audience("spiffe://test.quarkus.io/resource-server")
                .spiffeId("spiffe://test.quarkus.io/test-workload")
                .build();

        assertThat(request.audiences()).containsExactly("spiffe://test.quarkus.io/resource-server");
        assertThat(request.spiffeId()).isEqualTo("spiffe://test.quarkus.io/test-workload");
    }

    @Test
    void builderWithAudienceSet() {
        JwtSvidRequest request = JwtSvidRequest.builder()
                .audiences(Set.of(
                        "spiffe://test.quarkus.io/resource-server",
                        "spiffe://test.quarkus.io/api-gateway"))
                .build();

        assertThat(request.audiences()).containsExactlyInAnyOrder(
                "spiffe://test.quarkus.io/resource-server",
                "spiffe://test.quarkus.io/api-gateway");
    }
}
