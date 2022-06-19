package org.michalvavrik.qute.development;

import java.util.Set;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import io.quarkus.qute.Location;
import io.quarkus.qute.Template;
import io.quarkus.qute.TemplateInstance;

@Path("/hello")
public class ExampleResource {

    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String hello() {
        return "hello";
    }

    @Location("/home/mvavrik/sources/quarkus/integration-tests/quarkus-development-michal/michal-templates/basic.html")
    //    @Location("/home/mvavrik/Downloads/qute-development/michal-templates/basic.html")
    //    @Location("src/main/resources/templates/regular")
    Template report;

    @Location("regular")
    Template regular;

    @GET
    @Path("/template")
    public TemplateInstance get() {
        return report.data("name", "Qute Template");
    }

    @GET
    @Path("/data-namespace")
    public TemplateInstance getDataNamespaceTemplate() {
        var item = new Item("TOP-LEVEL", Set.of(
                new Item("NESTED_1", null),
                new Item("NESTED_2", null),
                new Item("NESTED_3", null)));
        return regular.data("item", item);
    }

}
