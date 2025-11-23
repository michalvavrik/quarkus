package io.quarkus.hibernate.reactive.rest.data.panache.deployment.security;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;

import java.util.Collections;

import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.hibernate.reactive.rest.data.panache.PanacheEntityResource;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.entity.AbstractEntity;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.entity.AbstractItem;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.entity.Collection;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.entity.CollectionsResource;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.entity.EmptyListItem;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.entity.EmptyListItemsResource;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.entity.Item;
import io.quarkus.hibernate.reactive.rest.data.panache.deployment.entity.ItemsResource;
import io.quarkus.rest.data.panache.ResourceProperties;
import io.quarkus.test.QuarkusUnitTest;
import io.smallrye.mutiny.Uni;

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
    void shouldCopyAdditionalMethodsAsResources() {
        given().accept("application/json")
                .when().get("/collections/name/full collection")
                .then().statusCode(200)
                .and().body("id", is("full"))
                .and().body("name", is("full collection"));
    }

    @Test
    void shouldAdditionalMethodsSupportHal() {
        given().accept("application/hal+json")
                .when().get("/collections/name/full collection")
                .then().statusCode(200)
                .and().body("id", is("full"))
                .and().body("name", is("full collection"))
                .and().body("_links.addByName.href", containsString("/name/full"));
    }

    @ResourceProperties(hal = true, paged = false, halCollectionName = "item-collections")
    public interface CollectionsResource extends PanacheEntityResource<Collection, String> {
        @GET
        @Path("/name/{name}")
        default Uni<Collection> findByName(@PathParam("name") String name) {
            return Collection.find("name = :name", Collections.singletonMap("name", name)).singleResult();
        }

        @POST
        @Path("/name/{name}")
        default Uni<Collection> addByName(@PathParam("name") String name) {
            Collection collection = new Collection();
            collection.id = name;
            collection.name = name;
            return Collection.persist(collection).onItem().transform(res -> collection);
        }
    }
}
