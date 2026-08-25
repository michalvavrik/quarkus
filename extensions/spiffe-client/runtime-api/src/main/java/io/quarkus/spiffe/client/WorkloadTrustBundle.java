package io.quarkus.spiffe.client;

import java.security.cert.X509Certificate;
import java.util.List;

import io.smallrye.common.annotation.Experimental;

/**
 * X.509 trust bundle: the CA certificates (trust anchors) used to validate the X.509-SVID that a peer
 * presents during an mTLS handshake.
 */
@Experimental("This API is currently experimental and might get changed")
public interface WorkloadTrustBundle {

    /**
     * Returns the CA certificates (trust anchors) of the workload's trust domain, used to validate the
     * X.509-SVID presented by a peer (for example, a server) during an mTLS handshake. Never null or empty.
     */
    List<X509Certificate> chain();

    /**
     * Returns the CA certificates (trust anchors) of the workload's trust domain in PEM format, used to
     * validate the X.509-SVID presented by a peer (for example, a server) during an mTLS handshake.
     * Never null or empty.
     */
    List<String> chainPem();

}
