package io.quarkus.keycloak.admin.client.common;

public enum AuthMethod {
    /**
     * Authorization provider is required.
     */
    AUTH_TOKEN,

    /**
     * Analogous to the 'client_credentials' grant type.
     * Client id and secret are required.
     */
    CLIENT_CREDENTIALS,

    /**
     * Analogous to the 'password' grant type.
     * Username, password and client id are required.
     */
    PASSWORD;

    String grantType() {
        if (this == AUTH_TOKEN) {
            throw new IllegalStateException();
        } else {
            return this.toString().toLowerCase();
        }
    }
}
