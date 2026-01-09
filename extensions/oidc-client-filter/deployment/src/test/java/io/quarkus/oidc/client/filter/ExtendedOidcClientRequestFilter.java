package io.quarkus.oidc.client.filter;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;

import io.quarkus.oidc.client.filter.api.OidcClientRequestFilter;

@Priority(Priorities.AUTHENTICATION)
public class ExtendedOidcClientRequestFilter extends OidcClientRequestFilter {
}
