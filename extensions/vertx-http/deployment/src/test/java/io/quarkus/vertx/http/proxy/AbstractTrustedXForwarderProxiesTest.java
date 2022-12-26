package io.quarkus.vertx.http.proxy;

import java.util.List;

import org.hamcrest.Matchers;
import org.jboss.shrinkwrap.api.asset.StringAsset;

import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.vertx.http.ForwardedHandlerInitializer;
import io.restassured.RestAssured;
import io.restassured.response.ValidatableResponse;

public abstract class AbstractTrustedXForwarderProxiesTest {

    private static final String SUCCESS = "https|somehost|backend:4444|/path|https://somehost/path";

    protected static QuarkusUnitTest createTrustedProxyUnitTest(String trustedProxy) {
        return createTrustedProxyUnitTest(List.of(trustedProxy));
    }

    protected static QuarkusUnitTest createTrustedProxyUnitTest(List<String> trustedProxies) {
        final String trustedProxiesAsStr;
        if (trustedProxies.isEmpty()) {
            trustedProxiesAsStr = "";
        } else {
            trustedProxiesAsStr = "quarkus.http.proxy.trusted-x-forwarded-proxies=" + String.join(",", trustedProxies) + "\n";
        }
        return new QuarkusUnitTest()
                .withApplicationRoot((jar) -> jar
                        .addClasses(ForwardedHandlerInitializer.class)
                        .addAsResource(new StringAsset("quarkus.http.proxy.proxy-address-forwarding=true\n" +
                                "quarkus.http.proxy.allow-x-forwarded=true\n" +
                                "quarkus.http.proxy.enable-forwarded-host=true\n" +
                                "quarkus.http.proxy.enable-forwarded-prefix=true\n" +
                                trustedProxiesAsStr +
                                "quarkus.http.proxy.forwarded-host-header=X-Forwarded-Server"),
                                "application.properties"));
    }

    protected static ValidatableResponse request() {
        return RestAssured.given()
                .header("Forwarded", "proto=http;for=backend2:5555;host=somehost2")
                .header("X-Forwarded-Ssl", "on")
                .header("X-Forwarded-For", "backend:4444")
                .header("X-Forwarded-Server", "somehost")
                .get("/path")
                .then();
    }

    protected static void assertRequestSuccess() {
        request().body(Matchers.equalTo(SUCCESS));
    }

}
