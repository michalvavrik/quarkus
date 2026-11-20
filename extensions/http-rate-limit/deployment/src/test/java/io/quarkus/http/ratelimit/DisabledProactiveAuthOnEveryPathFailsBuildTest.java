package io.quarkus.http.ratelimit;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.runtime.configuration.ConfigurationException;
import io.quarkus.test.QuarkusExtensionTest;

/**
 * A post-authentication rule authenticates every request to its paths when it arrives. With a rule on every path,
 * {@code quarkus.http.auth.proactive=false} would silently have no effect, which fails the build. A rule on some of the
 * paths is accepted, see {@link DisabledProactiveAuthTest}.
 */
public class DisabledProactiveAuthOnEveryPathFailsBuildTest {

    private static final String PREFIX = "quarkus.http.rate-limit.rules.api.";

    @RegisterExtension
    static final QuarkusExtensionTest config = new QuarkusExtensionTest()
            .overrideConfigKey("quarkus.http.auth.proactive", "false")
            .overrideConfigKey(PREFIX + "paths", "/*")
            .overrideConfigKey(PREFIX + "phase", "post-authentication")
            .overrideConfigKey(PREFIX + "request-key", "principal")
            .overrideRuntimeConfigKey(PREFIX + "permits", "1")
            .overrideRuntimeConfigKey(PREFIX + "window", "1m")
            .assertException(t -> assertThat(t).rootCause().isInstanceOf(ConfigurationException.class)
                    .hasMessageContaining("Rate limit rule 'api' has phase=post-authentication and matches every path,"
                            + " so it authenticates every request and quarkus.http.auth.proactive=false has no effect."
                            + " Set quarkus.http.auth.proactive=true, or restrict the paths or methods of the rule."));

    @Test
    void buildFails() {
        // the extension asserts the build failure
    }
}
