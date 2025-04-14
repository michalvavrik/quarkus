package io.quarkus.websockets.next.test.security;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;
import java.time.Duration;
import java.util.Queue;
import java.util.concurrent.LinkedBlockingDeque;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;

import jakarta.enterprise.context.SessionScoped;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.security.Authenticated;
import io.quarkus.security.identity.AuthenticationRequestContext;
import io.quarkus.security.identity.IdentityProvider;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.identity.request.UsernamePasswordAuthenticationRequest;
import io.quarkus.security.runtime.QuarkusPrincipal;
import io.quarkus.security.runtime.QuarkusSecurityIdentity;
import io.quarkus.test.QuarkusUnitTest;
import io.quarkus.test.common.http.TestHTTPResource;
import io.quarkus.websockets.next.OnTextMessage;
import io.smallrye.mutiny.Multi;
import io.smallrye.mutiny.Uni;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpHeaders;
import io.vertx.core.http.WebSocket;
import io.vertx.core.http.WebSocketClient;
import io.vertx.core.http.WebSocketConnectOptions;
import io.vertx.ext.auth.authentication.UsernamePasswordCredentials;

public class SecurityIdentityPropagationTest {

    @Inject
    Vertx vertx;

    @TestHTTPResource("echo-multi-produce")
    URI echoMultiProduce;

    @RegisterExtension
    public static final QuarkusUnitTest test = new QuarkusUnitTest()
            .withApplicationRoot(root -> {
                root.addClasses(EchoMultiProduce.class, TrivialIdentityProvider.class, MyService.class);
            });

    @Test
    public void testEchoMultiProduce() throws Exception {
        assertEcho("hello");
    }

    private void assertEcho(String payload) throws Exception {
        assertEcho(payload, (ws, queue) -> {
            ws.textMessageHandler(msg -> {
                queue.add(msg);
            });
            ws.writeTextMessage(payload);
        });
    }

    private void assertEcho(String payload, BiConsumer<WebSocket, Queue<String>> action) throws Exception {
        WebSocketClient client = vertx.createWebSocketClient();
        try {
            LinkedBlockingDeque<String> message = new LinkedBlockingDeque<>();
            client
                    .connect(basicAuth())
                    .onComplete(r -> {
                        if (r.succeeded()) {
                            WebSocket ws = r.result();
                            action.accept(ws, message);
                        } else {
                            throw new IllegalStateException(r.cause());
                        }
                    });
            assertEquals("Pete %s Pete".formatted(payload), message.poll(40, TimeUnit.SECONDS));
        } finally {
            client.close().toCompletionStage().toCompletableFuture().get();
        }
    }

    private WebSocketConnectOptions basicAuth() {
        return new WebSocketConnectOptions().addHeader(HttpHeaders.AUTHORIZATION.toString(),
                new UsernamePasswordCredentials("username", "password")
                        .applyHttpChallenge(null).toHttpAuthorization())
                .setHost(echoMultiProduce.getHost()).setPort(echoMultiProduce.getPort())
                .setURI(echoMultiProduce.getPath());
    }

    @Authenticated
    @io.quarkus.websockets.next.WebSocket(path = "/echo-multi-produce")
    public static class EchoMultiProduce {

        @Inject
        SecurityIdentity securityIdentity;

        @Inject
        MyService service;

        @OnTextMessage
        Multi<String> echo(String msg) {
            return service.echo(securityIdentity.getPrincipal().getName() + " " + msg);
        }

    }

    @SessionScoped
    public static class MyService {

        @Inject
        SecurityIdentity securityIdentity;

        Multi<String> echo(String msg) {
            return Multi.createFrom().item(msg)
                    .onItem().call(i ->
                    // Delay the emission until the returned uni emits its item
                    Uni.createFrom().nullItem().onItem().delayIt().by(Duration.ofSeconds(10)))
                    .map(m -> m + " " + securityIdentity.getPrincipal().getName());
        }

    }

    @Singleton
    public static class TrivialIdentityProvider implements IdentityProvider<UsernamePasswordAuthenticationRequest> {

        @Override
        public Class<UsernamePasswordAuthenticationRequest> getRequestType() {
            return UsernamePasswordAuthenticationRequest.class;
        }

        @Override
        public Uni<SecurityIdentity> authenticate(UsernamePasswordAuthenticationRequest usernamePasswordAuthenticationRequest,
                AuthenticationRequestContext authenticationRequestContext) {
            return Uni.createFrom().item(QuarkusSecurityIdentity.builder()
                    .setPrincipal(new QuarkusPrincipal("Pete"))
                    .build());
        }
    }
}
