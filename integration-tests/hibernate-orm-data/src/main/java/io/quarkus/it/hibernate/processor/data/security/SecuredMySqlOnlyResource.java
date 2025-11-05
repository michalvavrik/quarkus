package io.quarkus.it.hibernate.processor.data.security;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;

import org.jboss.resteasy.reactive.RestPath;

import io.quarkus.it.hibernate.processor.data.pusqlonly.SecuredMySqlOnlyRepository;

@ApplicationScoped
@Produces("application/json")
@Consumes("application/json")
@Path("/secured/data/sqlonly")
public class SecuredMySqlOnlyResource {

    @Inject
    SecuredMySqlOnlyRepository repository;

    @PUT
    @Transactional
    @Path("/myuser/{id}")
    public void insert(@RestPath Integer id, SecuredMySqlOnlyRepository.MyUserDto user) {
        repository.insert(id, user.username(), user.role());
    }

    @GET
    @Transactional
    @Path("/myuser/by/username/{name}")
    public SecuredMySqlOnlyRepository.MyUserDto getByName(@RestPath String name) {
        return repository.findByUsername(name).orElseThrow(NotFoundException::new);
    }

}
