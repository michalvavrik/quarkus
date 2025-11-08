package io.quarkus.security.deployment;

import java.util.List;
import java.util.function.Predicate;

import org.jboss.jandex.ClassInfo;
import org.jboss.jandex.MethodInfo;

import io.quarkus.security.spi.SecurityTransformer;

final class DenyUnannotatedPredicate implements Predicate<ClassInfo> {

    private final SecurityTransformer helper;

    DenyUnannotatedPredicate(SecurityTransformer helper) {
        this.helper = helper;
    }

    @Override
    public boolean test(ClassInfo classInfo) {
        List<MethodInfo> methods = classInfo.methods();
        return !helper.hasSecurityAnnotation(classInfo)
                && methods.stream().anyMatch(helper::hasSecurityAnnotation);
    }
}
