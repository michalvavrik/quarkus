package io.quarkus.vertx.http.proxy;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

public class TrustedXForwarderProxiesFailureTest extends AbstractTrustedXForwarderProxiesTest {

    @RegisterExtension
    static final QuarkusUnitTest config = createTrustedProxyUnitTest("1.2.3.4");

    @Test
    public void testHeadersAreIgnored() {
        request()
                // we don't check port of 127.0.0.1 as that's subject to change
                .body(Matchers.startsWith("http|localhost:8081|127.0.0.1:"))
                .body(Matchers.endsWith("|/path|http://localhost:8081/path"));
        // without 'quarkus.http.proxy.trusted-x-forwarded-proxies=1.2.3.4' config property
        // response would be: 'https|somehost|backend:4444|/path|https://somehost/path'
    }

}
