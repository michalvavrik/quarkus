package io.quarkus.security.spi;

import static java.util.stream.Collectors.toSet;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;

import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.AnnotationOverlay;
import org.jboss.jandex.AnnotationTarget;
import org.jboss.jandex.AnnotationTransformation;
import org.jboss.jandex.ClassInfo;
import org.jboss.jandex.Declaration;
import org.jboss.jandex.DotName;
import org.jboss.jandex.IndexView;
import org.jboss.jandex.MethodInfo;

import io.quarkus.builder.item.SimpleBuildItem;
import io.quarkus.security.spi.SecurityTransformerHelper.AuthorizationType;

/**
 * A build item that serves as a builder for the {@link SecurityTransformerHelper}.
 */
public final class SecurityTransformerHelperBuildItem extends SimpleBuildItem {

    private record SecurityTransformerHelperCache(IndexView indexView, SecurityTransformerHelper helper) {
    }

    private final Collection<AnnotationTransformation> interfaceTransformations;
    private final Map<AuthorizationType, Set<DotName>> authorizationTypeToSecurityAnnotations;
    private final Set<DotName> allSecurityAnnotations;
    private final Predicate<ClassInfo> isInterfaceWithTransformations;
    private final Collection<SecurityTransformerHelperCache> securityTransformerHelperCache;

    public SecurityTransformerHelperBuildItem(Collection<AnnotationTransformation> interfaceTransformations,
            Map<AuthorizationType, Set<DotName>> authorizationTypeToSecurityAnnotations,
            Predicate<ClassInfo> isInterfaceWithTransformations) {
        this.interfaceTransformations = (interfaceTransformations == null || interfaceTransformations.isEmpty()) ? null
                : Collections.unmodifiableCollection(interfaceTransformations);
        this.authorizationTypeToSecurityAnnotations = Collections.unmodifiableMap(authorizationTypeToSecurityAnnotations);
        this.isInterfaceWithTransformations = isInterfaceWithTransformations;
        this.allSecurityAnnotations = getAllSecurityAnnotations(authorizationTypeToSecurityAnnotations);
        this.securityTransformerHelperCache = new CopyOnWriteArrayList<>();
    }

    public static SecurityTransformerHelper createSecurityTransformerHelper(IndexView indexView,
            Optional<SecurityTransformerHelperBuildItem> optionalHelperBuildItem) {
        return optionalHelperBuildItem.orElseThrow().createHelper(indexView);
    }

    private SecurityTransformerHelper createHelper(IndexView indexView) {
        // this is cached because the annotation overlay has some cache which we can leverage
        for (SecurityTransformerHelperCache cache : securityTransformerHelperCache) {
            if (cache.indexView == indexView) {
                return cache.helper;
            }
        }
        var helper = new SecurityTransformerHelperImpl(AnnotationOverlay.builder(indexView, interfaceTransformations).build());
        securityTransformerHelperCache.add(new SecurityTransformerHelperCache(indexView, helper));
        return helper;
    }

    private Set<DotName> getSecurityAnnotations(AuthorizationType[] authorizationTypes) {
        if (authorizationTypes == null || authorizationTypes.length == 0
                || authorizationTypes.length == AuthorizationType.values().length) {
            return allSecurityAnnotations;
        }
        Set<DotName> result = new HashSet<>();
        for (var authorizationType : authorizationTypes) {
            var securityAnnotations = authorizationTypeToSecurityAnnotations.get(authorizationType);
            if (securityAnnotations != null) {
                result.addAll(securityAnnotations);
            }
        }
        return result;
    }

    private static Set<DotName> getAllSecurityAnnotations(
            Map<AuthorizationType, Set<DotName>> authorizationTypeToSecurityAnnotations) {
        return authorizationTypeToSecurityAnnotations.values().stream()
                .filter(Objects::nonNull)
                .flatMap(Collection::stream)
                .collect(toSet());
    }

    final class SecurityTransformerHelperImpl implements SecurityTransformerHelper {

        private final AnnotationOverlay annotationOverlay;

        private SecurityTransformerHelperImpl(AnnotationOverlay annotationOverlay) {
            this.annotationOverlay = annotationOverlay;
        }

        @Override
        public Collection<AnnotationInstance> getAnnotations(DotName securityAnnotationName) {
            return getAnnotations(securityAnnotationName, false);
        }

        @Override
        public Collection<AnnotationInstance> getAnnotationsWithRepeatable(DotName securityAnnotationName) {
            return getAnnotations(securityAnnotationName, true);
        }

        @Override
        public boolean hasSecurityAnnotation(AnnotationTarget annotationTarget, AuthorizationType... authorizationTypes) {
            return findFirstSecurityAnnotation(annotationTarget, authorizationTypes).isPresent();
        }

        @Override
        public boolean isSecurityAnnotation(AnnotationInstance annotationInstance, AuthorizationType... authorizationTypes) {
            if (authorizationTypes == null || authorizationTypes.length == 0) {
                authorizationTypes = AuthorizationType.values();
            }
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
        public boolean isSecurityAnnotation(Collection<AnnotationInstance> annotationInstances) {
            for (AnnotationInstance annotationInstance : annotationInstances) {
                if (isSecurityAnnotation(annotationInstance)) {
                    return true;
                }
            }
            return false;
        }

        @Override
        public Optional<AnnotationInstance> findFirstSecurityAnnotation(Collection<AnnotationInstance> annotationInstances) {
            for (AnnotationInstance annotationInstance : annotationInstances) {
                if (isSecurityAnnotation(annotationInstance)) {
                    return Optional.of(annotationInstance);
                }
            }
            return Optional.empty();
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

        private boolean hasSecurityAnnotationDetectedByIndex(MethodInfo methodInfo) {
            for (AnnotationInstance instance : methodInfo.annotations()) {
                if (allSecurityAnnotations.contains(instance.name())) {
                    return true;
                }
            }
            return false;
        }

        private boolean shouldCheckForSecurityAnnotations(ClassInfo ci, HashSet<String> checkedInterfaces) {
            return isInterfaceWithTransformations.test(ci) && checkedInterfaces.add(ci.name().toString());
        }

        private Collection<AnnotationInstance> getImplementorsSecurityAnnotations(DotName securityAnnotationName,
                ClassInfo securedInterface,
                boolean repeatable) {
            Collection<AnnotationInstance> result = null;
            // secured interface implementations may have their security annotations added by the annotation
            // transformer which is not visible for the index, therefore we go over all the implementors and
            // collect for each secured method we must add its secured implementor method if it wasn't found
            // directly by the index, we leverage annotation transformations and find not indexed secured methods

            // this will go over all the implementation methods and catch all security annotations added by the transformer;
            // naturally it may happen that some method will be collected more than once, which is why we must store
            // method infos in a set
            for (var implementation : annotationOverlay.index().getAllKnownImplementations(securedInterface.name())) {
                // we don't need to care about the class-level transformation annotations, because we only support method
                // security and all the interface class-level annotations are transformed to individual methods instead
                for (var implementationMethod : implementation.methods()) {
                    if (hasSecurityAnnotationDetectedByIndex(implementationMethod)) {
                        // this annotation was indexed, therefore already collected
                        continue;
                    }
                    if (repeatable) {
                        var annotations = annotationOverlay.annotationsWithRepeatable(implementationMethod,
                                securityAnnotationName);
                        if (!annotations.isEmpty()) {
                            if (result == null) {
                                result = new HashSet<>();
                            }
                            result.addAll(annotations);
                        }
                    } else {
                        if (annotationOverlay.hasAnnotation(implementationMethod, securityAnnotationName)) {
                            if (result == null) {
                                result = new HashSet<>();
                            }
                            result.add(annotationOverlay.annotation(implementationMethod, securityAnnotationName));
                        }
                    }
                }
            }
            return result;
        }

        private Collection<AnnotationInstance> getAnnotations(DotName securityAnnotationName, boolean repeatable) {
            final Collection<AnnotationInstance> indexedAnnotationInstances;
            if (repeatable) {
                indexedAnnotationInstances = annotationOverlay.index().getAnnotationsWithRepeatable(securityAnnotationName,
                        annotationOverlay.index());
            } else {
                indexedAnnotationInstances = annotationOverlay.index().getAnnotations(securityAnnotationName);
            }

            if (interfaceTransformations == null) {
                return indexedAnnotationInstances;
            }

            var checkedInterfaces = new HashSet<String>();
            // add security annotation instances from interfaces direct implementors
            var result = new HashSet<>(indexedAnnotationInstances);
            for (var annotationInstance : indexedAnnotationInstances) {
                final ClassInfo declaringClass;
                if (annotationInstance.target().kind() == AnnotationTarget.Kind.METHOD) {
                    declaringClass = annotationInstance.target().asMethod().declaringClass();
                } else if (annotationInstance.target().kind() == AnnotationTarget.Kind.CLASS) {
                    declaringClass = annotationInstance.target().asClass();
                } else {
                    // illegal state - this shouldn't happen
                    continue;
                }
                if (shouldCheckForSecurityAnnotations(declaringClass, checkedInterfaces)) {
                    var implementorSecurityAnnotation = getImplementorsSecurityAnnotations(securityAnnotationName,
                            declaringClass, repeatable);
                    if (implementorSecurityAnnotation != null) {
                        result.addAll(implementorSecurityAnnotation);
                    }
                }
            }
            return Collections.unmodifiableCollection(result);
        }
    }

}
