package io.quarkus.it.hibernate.processor.data;

import jakarta.inject.Inject;
import jakarta.ws.rs.Path;

@Path("/security/")
public class SecuredRepositoriesResource {

    @Inject
    MySqlOnlyResource mySqlOnlyResource;

    @Inject
    MyOtherEntityResource myOtherEntityResource;

    @Inject
    MyEntityResource myEntityResource;

    @Path("sql-only-sub")
    public MySqlOnlyResource mySqlOnlySubResource() {
        return mySqlOnlyResource;
    }

    @Path("data-other-sub")
    public MyOtherEntityResource myOtherEntitySubResource() {
        return myOtherEntityResource;
    }

    @Path("data-sub")
    public MyEntityResource myEntitySubResource() {
        return myEntityResource;
    }

}
