package org.jboss.resteasy.reactive.server.vertx;

import java.util.function.Consumer;

import org.jboss.resteasy.reactive.server.handlers.RestInitialHandler;

import io.vertx.core.Handler;
import io.vertx.ext.web.RoutingContext;

public class ResteasyReactiveVertxHandler implements Handler<RoutingContext> {

    private final Consumer<RoutingContext> eventCustomizer;
    private final RestInitialHandler handler;

    public ResteasyReactiveVertxHandler(Consumer<RoutingContext> eventCustomizer, RestInitialHandler handler) {
        this.eventCustomizer = eventCustomizer;
        this.handler = handler;
    }

    @Override
    public void handle(RoutingContext event) {
        eventCustomizer.accept(event);
        handler.beginProcessing(event);
    }
}
