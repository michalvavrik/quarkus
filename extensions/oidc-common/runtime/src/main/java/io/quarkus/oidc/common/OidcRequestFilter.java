package io.quarkus.oidc.common;

import java.util.function.Supplier;

import io.smallrye.mutiny.Uni;
import io.vertx.mutiny.core.buffer.Buffer;
import io.vertx.mutiny.ext.web.client.HttpRequest;

/**
 * Request filter which can be used to customize requests such as the verification JsonWebKey set and token grant requests
 * which are made from the OIDC adapter to the OIDC provider.
 * <p/>
 * Filter can be restricted to a specific OIDC endpoint with a {@link OidcEndpoint} annotation.
 */
public interface OidcRequestFilter {

    /**
     * OIDC request context which provides access to the HTTP request headers and body, as well as context properties.
     */
    class OidcRequestContext {
        final HttpRequest<Buffer> request;
        final OidcRequestContextProperties contextProperties;
        Buffer requestBody;

        public OidcRequestContext(HttpRequest<Buffer> request, Buffer requestBody,
                OidcRequestContextProperties contextProperties) {
            this.request = request;
            this.requestBody = requestBody;
            this.contextProperties = contextProperties;
        }

        public HttpRequest<Buffer> request() {
            return request;
        }

        public Buffer requestBody() {
            return requestBody;
        }

        public OidcRequestContextProperties contextProperties() {
            return contextProperties;
        }

        public void requestBody(Buffer buffer) {
            requestBody = buffer;
            contextProperties.put(OidcRequestContextProperties.REQUEST_BODY, buffer);
        }
    }

    /**
     * Filter OIDC request without blocking.
     * Blocking tasks must use the {@link #filter(OidcRequestContext, OidcBlockingContext)} method instead.
     *
     * @param requestContext the request context which provides access to the HTTP request headers and body, as well as context
     *        properties.
     */
    default void filter(OidcRequestContext requestContext) {
        throw new UnsupportedOperationException("filter(OidcRequestContext requestContext) method is not implemented");
    }

    /**
     * Filter OIDC request asynchronously.
     * Blocking tasks can be run with the {@link OidcBlockingContext#runBlocking(Supplier)} method.
     *
     * @param requestContext the request context which provides access to the HTTP request headers and body, as well
     *        as context properties.
     * @param blockingContext context object used to execute blocking tasks
     * @return {@link Uni}; must not be null
     */
    default Uni<Void> filter(OidcRequestContext requestContext, OidcBlockingContext<Void> blockingContext) {
        return Uni.createFrom().item(() -> {
            filter(requestContext);
            return null;
        });
    }
}
