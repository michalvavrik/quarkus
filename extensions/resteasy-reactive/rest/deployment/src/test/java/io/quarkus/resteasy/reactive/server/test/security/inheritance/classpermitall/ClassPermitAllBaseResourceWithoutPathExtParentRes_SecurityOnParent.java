package io.quarkus.resteasy.reactive.server.test.security.inheritance.classpermitall;

import jakarta.inject.Singleton;

@Singleton // this seems to be required when the @Path annotation is on a parent
public class ClassPermitAllBaseResourceWithoutPathExtParentRes_SecurityOnParent
        extends ClassPermitAllParentResourceWithPath_SecurityOnParent {
}
