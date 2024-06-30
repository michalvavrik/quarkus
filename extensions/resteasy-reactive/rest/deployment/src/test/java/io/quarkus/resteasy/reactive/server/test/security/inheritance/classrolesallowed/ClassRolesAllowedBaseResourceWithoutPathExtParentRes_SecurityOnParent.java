package io.quarkus.resteasy.reactive.server.test.security.inheritance.classrolesallowed;

import jakarta.inject.Singleton;

@Singleton // this seems to be required when the @Path annotation is on a parent
public class ClassRolesAllowedBaseResourceWithoutPathExtParentRes_SecurityOnParent
        extends ClassRolesAllowedParentResourceWithPath_SecurityOnParent {

}
