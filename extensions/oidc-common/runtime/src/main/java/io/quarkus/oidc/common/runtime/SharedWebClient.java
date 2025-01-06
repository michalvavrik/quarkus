package io.quarkus.oidc.common.runtime;

import io.vertx.ext.web.client.WebClientOptions;
import io.vertx.mutiny.core.Vertx;
import io.vertx.mutiny.ext.web.client.WebClient;

import java.util.ArrayList;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CopyOnWriteArraySet;

/**
 * A {@link WebClient} that allows us to share one web client between many OIDC clients
 * that shares same {@link WebClientOptions}.
 */
public final class SharedWebClient extends WebClient  {

    private final CopyOnWriteArraySet<String> clientIds;
    private final transient Object lock = new Object();
    private volatile boolean closed;

    private SharedWebClient(io.vertx.ext.web.client.WebClient delegate, ArrayList<String> clientIds) {
        super(delegate);
        // this creates CopyOnWriteArrayList to avoid synchronized block in CopyOnWriteArraySet in default impl.
        this.clientIds = new CopyOnWriteArraySet<>(new CopyOnWriteArrayList<>(clientIds));
        this.closed = false;
    }

    /**
     * Adds a client id to this client. This allows to share one {@link WebClient} between clients.
     * This method must stay package-private as we need to check that only clients with matching
     * {@link WebClientOptions} are added.
     *
     * @param clientId client id
     * @return false if this WebClient is already closed; that means you need a new `WebClient`
     */
    boolean addClientId(String clientId) {
        synchronized (lock) {
            if (closed) {
                return false;
            }
            clientIds.add(clientId);
            return true;
        }
    }

    @Override
    public void close() {
        throw new UnsupportedOperationException("SharedWebClient can only be closed for concrete clients, please use 'close(String clientId)' method instead");
    }

    public void close(String clientId) {
        Objects.requireNonNull(clientId, "clientId cannot be null");
        synchronized (lock) {
            clientIds.remove(clientId);
            if (clientIds.isEmpty()) {
                closed = true;
            }
        }
    }

    public static SharedWebClient create(Vertx vertx, WebClientOptions options, ArrayList<String> clientIds) {
        // this uses ArrayList to avoid extra cloning in CopyOnWriteArraySet; feel free to change it if needed
        var delegate = io.vertx.ext.web.client.WebClient.create(vertx.getDelegate(), options);
        return new SharedWebClient(delegate, clientIds);
    }
}
