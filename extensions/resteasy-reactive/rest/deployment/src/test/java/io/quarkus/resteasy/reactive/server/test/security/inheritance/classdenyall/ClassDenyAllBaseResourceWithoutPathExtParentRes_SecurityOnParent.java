package io.quarkus.resteasy.reactive.server.test.security.inheritance.classdenyall;

import jakarta.inject.Singleton;

@Singleton // this seems to be required when the @Path annotation is on a parent
public class ClassDenyAllBaseResourceWithoutPathExtParentRes_SecurityOnParent
        extends ClassDenyAllParentResourceWithPath_SecurityOnParent {

}
