package io.quarkus.security.spi;

import java.util.Collection;
import java.util.Optional;

import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.AnnotationTarget;
import org.jboss.jandex.DotName;

import io.quarkus.security.spi.SecurityTransformerHelperBuildItem.SecurityTransformerHelperImpl;

public sealed interface SecurityTransformerHelper permits SecurityTransformerHelperImpl {

    /**
     * Types of authorization we perform for registered security annotations.
     * These types are mutually exclusive.
     */
    enum AuthorizationType {
        /**
         * Security checks are performed for CDI beans and endpoints annotated with security annotations.
         */
        SECURITY_CHECK,
        /**
         * Authorization policies are performed for incoming requests.
         * They can be either global or restricted to certain methods by annotations.
         */
        AUTHORIZATION_POLICY
    }

    Collection<AnnotationInstance> getAnnotations(DotName securityAnnotationName, AuthorizationType... authorizationTypes);

    boolean hasSecurityAnnotation(AnnotationTarget annotationTarget, AuthorizationType... authorizationTypes);

    boolean isSecurityAnnotation(AnnotationInstance annotationInstance, AuthorizationType... authorizationTypes);

    Optional<AnnotationInstance> findFirstSecurityAnnotation(AnnotationTarget annotationTarget,
            AuthorizationType... authorizationTypes);

    default Collection<AnnotationInstance> getAnnotations(DotName securityAnnotationName) {
        return getAnnotations(securityAnnotationName, AuthorizationType.values());
    }

    default boolean hasSecurityAnnotation(AnnotationTarget annotationTarget) {
        return hasSecurityAnnotation(annotationTarget, AuthorizationType.values());
    }
}
