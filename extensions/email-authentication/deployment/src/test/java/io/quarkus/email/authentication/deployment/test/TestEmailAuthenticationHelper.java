package io.quarkus.email.authentication.deployment.test;

import io.restassured.RestAssured;
import io.restassured.filter.cookie.CookieFilter;
import io.restassured.response.ValidatableResponse;

final class TestEmailAuthenticationHelper {

    private final String tokenGenerationPath;
    private final String postLocation;
    private CookieFilter cookieFilter;

    TestEmailAuthenticationHelper(String tokenGenerationPath, String postLocation) {
        this.tokenGenerationPath = tokenGenerationPath;
        this.postLocation = postLocation;
    }

    ValidatableResponse requestTokenFor(String username) {
        cookieFilter = new CookieFilter();
        return RestAssured.given()
                .formParam("j_username", "admin")
                .post(tokenGenerationPath)
                .then();
    }

    void clear() {
        cookieFilter = new CookieFilter();
    }
}
