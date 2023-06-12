package io.quarkus.oidc.state.manager.db;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;

@Entity
@Table(name = "token-state-entity")
public class TokenStateEntity {

    private long id;
    private String idToken;
    private String accessToken;
    private String refreshToken;

}
