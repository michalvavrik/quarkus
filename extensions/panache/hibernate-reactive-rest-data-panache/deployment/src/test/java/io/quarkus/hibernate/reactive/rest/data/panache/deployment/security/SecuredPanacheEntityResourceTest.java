package io.quarkus.hibernate.reactive.rest.data.panache.deployment.security;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.hibernate.reactive.rest.data.panache.deployment.entity.AbstractEntity;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.entity.AbstractItem;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.entity.Collection;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.entity.EmptyListItem;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.entity.EmptyListItemsResource;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.entity.Item;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.entity.ItemsResource;
import io.quarkus.test.QuarkusUnitTest;

class SecuredPanacheEntityResourceTest {

    @RegisterExtension
    static final QuarkusUnitTest TEST = new QuarkusUnitTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(Collection.class, AbstractEntity.class, AbstractItem.class,
                            Item.class, ItemsResource.class, CollectionsResource.class,
                            EmptyListItem.class, EmptyListItemsResource.class)
                    .addAsResource("application.properties")
                    .addAsResource("import.sql"));

    @Test
    void shouldAdditionalMethodsSupportHal() {
        given().accept("application/hal+json")
                .when().get("/collections/name/full collection")
                .then().statusCode(200)
                .and().body("id", is("full"))
                .and().body("name", is("full collection"))
                .and().body("_links.addByName.href", containsString("/name/full"));
    }

    @Test
    void shouldCopyAdditionalMethodsAsResources() {
        given().accept("application/json")
                .when().post("/collections/name/mycollection")
                .then().statusCode(200)
                .and().body("id", is("mycollection"))
                .and().body("name", is("mycollection"));
    }
}
