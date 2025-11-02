package io.quarkus.security.spi;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.AnnotationOverlay;
import org.jboss.jandex.AnnotationTarget;
import org.jboss.jandex.AnnotationTransformation;
import org.jboss.jandex.Declaration;
import org.jboss.jandex.DotName;
import org.jboss.jandex.IndexView;

import io.quarkus.builder.item.SimpleBuildItem;
import io.quarkus.security.spi.SecurityTransformerHelper.AuthorizationType;

/**
 * A build item that serves as a builder for the {@link SecurityTransformerHelper}.
 */
public final class SecurityTransformerHelperBuildItem extends SimpleBuildItem {

    private final Collection<AnnotationTransformation> interfaceTransformations;
    private final Map<AuthorizationType, Set<DotName>> authorizationTypeToSecurityAnnotations;

    public SecurityTransformerHelperBuildItem(Collection<AnnotationTransformation> interfaceTransformations,
            Map<AuthorizationType, Set<DotName>> authorizationTypeToSecurityAnnotations) {
        this.interfaceTransformations = Collections.unmodifiableCollection(interfaceTransformations);
        this.authorizationTypeToSecurityAnnotations = Collections.unmodifiableMap(authorizationTypeToSecurityAnnotations);
    }

    public static SecurityTransformerHelper createSecurityTransformerHelper(IndexView indexView,
            Optional<SecurityTransformerHelperBuildItem> optionalHelperBuildItem) {
        return optionalHelperBuildItem.orElseThrow().createHelper(indexView);
    }

    private SecurityTransformerHelper createHelper(IndexView indexView) {
        return new SecurityTransformerHelperImpl(AnnotationOverlay.builder(indexView, interfaceTransformations).build());
    }

    final class SecurityTransformerHelperImpl implements SecurityTransformerHelper {

        private final AnnotationOverlay annotationOverlay;

        private SecurityTransformerHelperImpl(AnnotationOverlay annotationOverlay) {
            this.annotationOverlay = annotationOverlay;
        }

        @Override
        public Collection<AnnotationInstance> getAnnotations(DotName securityAnnotationName,
                AuthorizationType... authorizationTypes) {
            var annotationInstances = annotationOverlay.index().getAnnotations(securityAnnotationName);
            // FIXME interface transformation instances
            return annotationInstances;
        }

        @Override
        public boolean hasSecurityAnnotation(AnnotationTarget annotationTarget, AuthorizationType... authorizationTypes) {
            return findFirstSecurityAnnotation(annotationTarget, authorizationTypes).isPresent();
        }

        @Override
        public boolean isSecurityAnnotation(AnnotationInstance annotationInstance, AuthorizationType... authorizationTypes) {
            var securityAnnotationName = annotationInstance.name();
            for (var authorizationType : authorizationTypes) {
                var securityAnnotations = authorizationTypeToSecurityAnnotations.get(authorizationType);
                if (securityAnnotations != null && securityAnnotations.contains(securityAnnotationName)) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public Optional<AnnotationInstance> findFirstSecurityAnnotation(AnnotationTarget annotationTarget,
                AuthorizationType... authorizationTypes) {
            return findFirstSecurityAnnotation(annotationTarget.asDeclaration(), getSecurityAnnotations(authorizationTypes));
        }

        private Optional<AnnotationInstance> findFirstSecurityAnnotation(Declaration declaration,
                Set<DotName> securityAnnotations) {
            for (AnnotationInstance instance : annotationOverlay.annotations(declaration)) {
                if (securityAnnotations.contains(instance.name())) {
                    return Optional.of(instance);
                }
            }
            return Optional.empty();
        }

        private Set<DotName> getSecurityAnnotations(AuthorizationType[] authorizationTypes) {
            Set<DotName> result = new HashSet<>();
            for (var authorizationType : authorizationTypes) {
                var securityAnnotations = authorizationTypeToSecurityAnnotations.get(authorizationType);
                if (securityAnnotations != null) {
                    result.addAll(securityAnnotations);
                }
            }
            return result;
        }
    }

}
