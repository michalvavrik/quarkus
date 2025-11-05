package io.quarkus.it.hibernate.processor.data.security;

import java.util.List;

import jakarta.data.Order;
import jakarta.data.Sort;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;

import org.jboss.resteasy.reactive.RestPath;

import io.quarkus.it.hibernate.processor.data.pudefault.MyEntity;
import io.quarkus.it.hibernate.processor.data.pudefault.MyEntity_;
import io.quarkus.it.hibernate.processor.data.pudefault.SecuredMyRepository;

@ApplicationScoped
@Produces("application/json")
@Consumes("application/json")
@Path("/secured/data/")
public class SecuredMyEntityResource {

    @Inject
    SecuredMyRepository repository;

    @Path("/insert-root")
    @POST
    @Transactional
    public void insertForRootRole(MyEntity entity) {
        repository.insertRootRole(entity);
    }

    @Path("/insert-admin")
    @POST
    @Transactional
    public void insertForAdminRole(MyEntity entity) {
        repository.insertAdminRole(entity);
    }

    @Path("/insert-public")
    @POST
    @Transactional
    public void insertForEveryone(MyEntity entity) {
        repository.insert(entity);
    }

    @Path("/list-all-donald")
    @GET
    public List<MyEntity> listAllForDonald() {
        return repository.findAllForDonald(Order.by(Sort.asc(MyEntity_.NAME))).toList();
    }

    @Path("/list-all-george")
    @GET
    public List<MyEntity> listAllForGeorge() {
        return repository.findAllForGeorge(Order.by(Sort.asc(MyEntity_.NAME))).toList();
    }

    @GET
    @Transactional
    @Path("/by/name/{name}")
    public MyEntity getByName(@RestPath String name) {
        List<MyEntity> entities = repository.findByName(name);
        if (entities.isEmpty()) {
            throw new NotFoundException();
        }
        return entities.get(0);
    }

    @POST
    @Transactional
    @Path("/rename/{before}/to/{after}")
    public void rename(@RestPath String before, @RestPath String after) {
        MyEntity byName = getByName(before);
        byName.name = after;
        repository.update(byName);
    }

    @DELETE
    @Transactional
    @Path("/by/name/{name}")
    public void deleteByName(@RestPath String name) {
        repository.delete(name);
    }
}
