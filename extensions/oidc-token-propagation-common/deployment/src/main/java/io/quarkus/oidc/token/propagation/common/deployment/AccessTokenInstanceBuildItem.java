package io.quarkus.oidc.token.propagation.common.deployment;

import java.util.Objects;
import java.util.Set;

import org.jboss.jandex.AnnotationTarget;

import io.quarkus.builder.item.MultiBuildItem;

/**
 * Represents one {@link io.quarkus.oidc.token.propagation.common.AccessToken} annotation instance.
 */
public final class AccessTokenInstanceBuildItem extends MultiBuildItem {

    private final String clientName;
    private final boolean tokenExchange;
    private final AnnotationTarget annotationTarget;
    private final Set<String> methodNames;

    AccessTokenInstanceBuildItem(String clientName, Boolean tokenExchange, AnnotationTarget annotationTarget,
            Set<String> methodNames) {
        this.clientName = Objects.requireNonNull(clientName);
        this.tokenExchange = tokenExchange;
        this.annotationTarget = Objects.requireNonNull(annotationTarget);
        this.methodNames = Set.copyOf(methodNames);
    }

    String getClientName() {
        return clientName;
    }

    boolean exchangeTokenActivated() {
        return tokenExchange;
    }

    public AnnotationTarget getAnnotationTarget() {
        return annotationTarget;
    }

    public String targetClass() {
        return annotationTarget.asClass().name().toString();
    }

    Set<String> getMethodNames() {
        return methodNames;
    }
}
