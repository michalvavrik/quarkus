package io.quarkus.oidc.common;

import java.util.function.Supplier;

import io.smallrye.mutiny.Uni;

/**
 * OIDC Context that can be used to run blocking OIDC tasks.
 */
public interface OidcBlockingContext<T> {
    Uni<T> runBlocking(Supplier<T> function);
}
