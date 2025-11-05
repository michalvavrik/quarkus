package io.quarkus.it.hibernate.processor.data.pudefault;

import java.util.List;
import java.util.stream.Stream;

import jakarta.annotation.security.RolesAllowed;
import jakarta.data.Order;
import jakarta.data.repository.CrudRepository;
import jakarta.data.repository.Delete;
import jakarta.data.repository.Find;
import jakarta.data.repository.Insert;
import jakarta.data.repository.Query;
import jakarta.data.repository.Repository;
import jakarta.data.repository.Update;

import io.quarkus.security.PermissionsAllowed;

@Repository
public interface SecuredMyRepository extends CrudRepository<MyEntity, Integer> {

    @RolesAllowed("root")
    @Insert
    void insertRootRole(MyEntity entity);

    @RolesAllowed("admin")
    @Insert
    void insertAdminRole(MyEntity entity);

    @RolesAllowed("${donald}")
    @Find
    Stream<MyEntity> findAllForDonald(Order<MyEntity> order);

    @RolesAllowed("${george}")
    @Find
    Stream<MyEntity> findAllForGeorge(Order<MyEntity> order);

    @Query("select e from MyEntity e where e.name like :name")
    List<MyEntity> findByName(String name);

    @Delete
    void delete(String name);

    @PermissionsAllowed("rename-1")
    @Update
    void rename1(MyEntity entity);

    @PermissionsAllowed("rename-2")
    @Update
    void rename2(MyEntity entity);

}
