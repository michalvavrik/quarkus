package io.quarkus.hibernate.reactive.rest.data.panache.deployment.security;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.is;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.hibernate.reactive.rest.data.panache.deployment.repository.AbstractEntity;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.repository.AbstractItem;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.repository.Collection;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.repository.CollectionsRepository;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.repository.CollectionsResource;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.repository.EmptyListItem;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.repository.EmptyListItemsRepository;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.repository.EmptyListItemsResource;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.repository.Item;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.repository.ItemsRepository;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.repository.ItemsResource;
import io.quarkus.test.QuarkusUnitTest;

class SecuredPanacheRepositoryResourceTest {

    @RegisterExtension
    static final QuarkusUnitTest TEST = new QuarkusUnitTest()
            .withApplicationRoot((jar) -> jar
                    .addClasses(Collection.class, CollectionsResource.class, CollectionsRepository.class,
                            AbstractEntity.class, AbstractItem.class, Item.class, ItemsResource.class,
                            ItemsRepository.class, EmptyListItem.class, EmptyListItemsRepository.class,
                            EmptyListItemsResource.class)
                    .addAsResource("application.properties")
                    .addAsResource("import.sql"));

    @Test
    void shouldCopyAdditionalMethodsAsResources() {
        given().accept("application/json")
                .when().get("/collections/name/full collection")
                .then().statusCode(200)
                .and().body("id", is("full"))
                .and().body("name", is("full collection"));
    }
}
