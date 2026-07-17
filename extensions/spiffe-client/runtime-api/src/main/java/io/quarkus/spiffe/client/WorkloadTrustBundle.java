package io.quarkus.spiffe.client;

import java.security.cert.X509Certificate;
import java.util.List;

import io.smallrye.common.annotation.Experimental;

/**
 * X.509-SVID CA certificates for the workload's trust domain.
 */
@Experimental("This API is currently experimental and might get changed")
public interface WorkloadTrustBundle {

    /**
     * Returns the CA certificates (trust anchors) of the workload's trust domain. Never null or empty.
     */
    List<X509Certificate> chain();

    /**
     * Returns the CA certificates (trust anchors) of the workload's trust domain in the PEM format. Never null or empty.
     */
    List<String> chainPem();

}
