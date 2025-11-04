package io.quarkus.security.spi;

import static java.util.stream.Collectors.toSet;

import java.lang.reflect.Modifier;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import java.util.stream.Collectors;

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

    private final Map<AuthorizationType, Set<DotName>> authorizationTypeToSecurityAnnotations;
    private final Set<DotName> allSecurityAnnotations;
    private final Predicate<ClassInfo> isInterfaceWithTransformations;
    private final Map<IndexView, SecurityTransformerHelperCache> securityTransformerHelperCache;
    private final Set<DotName> securedInterfaceAnnotations;

    public SecurityTransformerHelperBuildItem(Map<AuthorizationType, Set<DotName>> authorizationTypeToSecurityAnnotations,
            Predicate<ClassInfo> isInterfaceWithTransformations, Set<DotName> securedInterfaceAnnotations) {
        this.authorizationTypeToSecurityAnnotations = Collections.unmodifiableMap(authorizationTypeToSecurityAnnotations);
        this.isInterfaceWithTransformations = isInterfaceWithTransformations;
        this.allSecurityAnnotations = getAllSecurityAnnotations(authorizationTypeToSecurityAnnotations);
        this.securedInterfaceAnnotations = Collections.unmodifiableSet(securedInterfaceAnnotations);
        this.securityTransformerHelperCache = new ConcurrentHashMap<>();
    }

    public static SecurityTransformerHelper createSecurityTransformerHelper(IndexView indexView,
            Optional<SecurityTransformerHelperBuildItem> optionalHelperBuildItem) {
        return createSecurityTransformerHelper(indexView, optionalHelperBuildItem.orElseThrow());
    }

    public static SecurityTransformerHelper createSecurityTransformerHelper(IndexView indexView,
            SecurityTransformerHelperBuildItem helperBuildItem) {
        return helperBuildItem.getOrCreateHelper(indexView);
    }

    private SecurityTransformerHelper getOrCreateHelper(IndexView indexView) {
        // this is cached because the annotation overlay has some cache which we can leverage
        return securityTransformerHelperCache.computeIfAbsent(indexView, index -> {
            // create helper
            var interfaceTransformations = createInterfaceTransformations(index);
            var helper = new SecurityTransformerHelperImpl(AnnotationOverlay.builder(index, interfaceTransformations).build(),
                    interfaceTransformations);
            return new SecurityTransformerHelperCache(index, helper);
        }).helper;
    }

    private Collection<AnnotationTransformation> createInterfaceTransformations(IndexView index) {
        if (isInterfaceWithTransformations != null) {
            // e.g. interface with Jakarta Data @Repository, it may or may not have security annotations
            var possiblySecuredInterfaces = securedInterfaceAnnotations.stream()
                    .map(index::getAnnotations)
                    .flatMap(Collection::stream)
                    .map(AnnotationInstance::target)
                    .filter(Objects::nonNull)
                    .filter(t -> t.kind() == AnnotationTarget.Kind.CLASS)
                    .map(AnnotationTarget::asClass)
                    .filter(ClassInfo::isInterface)
                    .collect(toSet());

            if (!possiblySecuredInterfaces.isEmpty()) {
                var interfaceNameToSecuredMethods = new HashMap<DotName, Set<MethodInfo>>();
                // collect secured methods
                possiblySecuredInterfaces.stream()
                        .map(ClassInfo::methods)
                        .flatMap(Collection::stream)
                        .filter(this::hasSecurityAnnotationDetectedByIndex)
                        .forEach(mi -> interfaceNameToSecuredMethods
                                .computeIfAbsent(mi.declaringClass().name(), k -> new HashSet<>()).add(mi));
                // collect secured methods based on class-level security annotation
                possiblySecuredInterfaces.stream()
                        .filter(this::hasSecurityAnnotationDetectedByIndex)
                        .forEach(ci -> {
                            var methodsSecuredByClassLevelAnnotation = ci.methods().stream()
                                    // prefer method-level security annotation
                                    .filter(mi -> !hasSecurityAnnotationDetectedByIndex(mi))
                                    .filter(mi -> !Modifier.isPrivate(mi.flags()))
                                    .collect(toSet());
                            if (!methodsSecuredByClassLevelAnnotation.isEmpty()) {
                                interfaceNameToSecuredMethods.computeIfAbsent(ci.name(), k -> new HashSet<>())
                                        .addAll(methodsSecuredByClassLevelAnnotation);
                            }
                        });
                if (!interfaceNameToSecuredMethods.isEmpty()) {
                    var interfaceNameToImplementationMethods = interfaceNameToSecuredMethods.keySet().stream()
                            .map(interfaceName -> Map.entry(interfaceName, index
                                    .getAllKnownImplementations(interfaceName)
                                    .stream()
                                    .map(ClassInfo::methods)
                                    .flatMap(Collection::stream)
                                    .filter(mi -> !Modifier.isPrivate(mi.flags()))
                                    .filter(m -> !hasSecurityAnnotationDetectedByIndex(m))
                                    .collect(toSet())))
                            .filter(e -> !e.getValue().isEmpty())
                            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
                    if (!interfaceNameToImplementationMethods.isEmpty()) {
                        // match unsecured implementation's methods with secured interface methods
                        // and add to the matched unsecured methods security annotations
                    }
                }
            }

            // FIXME: what needs to be done:
            //   - collect implementations
            //   - know what secured methods their interface has including ones inherited from
            //   - we add annotation collections, we need to cover also repeatable annotations
            //   - and we create the transformation when actually necessary based on index inside the build item
            var transformation = AnnotationTransformation.forMethods()
                    .whenMethod(mi -> false) // FIXME: impl. me!
                    .transform(ctx -> {
                        var methodInfo = ctx.declaration().asMethod();

                        // TODO: what about abstract classes impl. that interfaces, like abstract methods and non-abstract methods
                        // TODO: what needs to be done
                        //  - delete these notes
                        //  - document limitations for Jakarta Data and link it to the authz endpoints note re inheritance
                        //  - write tests, do not forget about interface extended by interface, class-level annotations,
                        //  static methods, default methods, overloaded methods, methods already annotated with sec annotation,
                        //  permissions allowed repeatable and not repeatable, permissions allowed meta annotations,
                        //  combinations between class-level and method-level annotations transformed/not transformed
                        //  - finish gathering of annotation instances for meta-annotations and repeatable permissions allowed
                        //  - review gathering of security checks annotations
                        //  - run all the related tests
                        // TODO: verify impl. of impl.
                        // TODO: add method with the same signature
                        // TODO: what if it is the default method?
                        // TODO: what if it is overloaded?
                        // TODO: what if it is present on multiple interfaces with the same signature?
                        // TODO: DOCUMENT THIS FOR JAKARTA DATA ONLY! it has it's limitations and it is not perfect
                        // TODO: what about static methods on interface?
                        // TODO: what about private methods
                        // TODO: make sure it is not already added (how, maybe Set? maybe go over the annotation instance again? maybe cache it?)
                    });

            // FIXME: can the transformation be null? oh yeah, if there is no implementation!
        }
        return null;
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

    private boolean hasSecurityAnnotationDetectedByIndex(Declaration declaration) {
        for (AnnotationInstance instance : declaration.declaredAnnotations()) {
            if (allSecurityAnnotations.contains(instance.name())) {
                return true;
            }
        }
        return false;
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
        private final Collection<AnnotationTransformation> interfaceTransformations;

        private SecurityTransformerHelperImpl(AnnotationOverlay annotationOverlay,
                Collection<AnnotationTransformation> interfaceTransformations) {
            this.annotationOverlay = annotationOverlay;
            this.interfaceTransformations = interfaceTransformations;
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

        @Override
        public Collection<AnnotationTransformation> getInterfaceTransformations() {
            return interfaceTransformations;
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
