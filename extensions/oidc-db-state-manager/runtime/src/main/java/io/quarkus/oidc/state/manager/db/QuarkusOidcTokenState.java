package io.quarkus.oidc.state.manager.db;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
public class QuarkusOidcTokenState {

    @Id
    private Long id;
    private String idToken;
    private String accessToken;
    private String refreshToken;
    // FIXME: index me!
    private String sessionKey;
    private Long expiredAt;

    public QuarkusOidcTokenState() {
        this.id = null;
        this.idToken = null;
        this.accessToken = null;
        this.refreshToken = null;
        this.sessionKey = null;
        this.expiredAt = null;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getIdToken() {
        return idToken;
    }

    public void setIdToken(String idToken) {
        this.idToken = idToken;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getSessionKey() {
        return sessionKey;
    }

    public void setSessionKey(String sessionKey) {
        this.sessionKey = sessionKey;
    }

    public Long getExpiredAt() {
        return expiredAt;
    }

    public void setExpiredAt(Long expiredAt) {
        this.expiredAt = expiredAt;
    }
}
