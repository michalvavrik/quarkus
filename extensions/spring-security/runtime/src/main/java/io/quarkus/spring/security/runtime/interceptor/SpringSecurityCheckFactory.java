package io.quarkus.spring.security.runtime.interceptor;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import io.quarkus.security.runtime.interceptor.check.AuthenticatedCheck;
import io.quarkus.security.runtime.interceptor.check.DenyAllCheck;
import io.quarkus.security.runtime.interceptor.check.PermitAllCheck;
import io.quarkus.security.runtime.interceptor.check.RolesAllowedCheck;
import io.quarkus.security.runtime.interceptor.check.SupplierRolesAllowedCheck;
import io.quarkus.security.spi.runtime.SecurityCheck;
import io.quarkus.spring.security.runtime.interceptor.check.AllDelegatingSecurityCheck;
import io.quarkus.spring.security.runtime.interceptor.check.AnonymousCheck;
import io.quarkus.spring.security.runtime.interceptor.check.AnyDelegatingSecurityCheck;
import io.quarkus.spring.security.runtime.interceptor.check.CombinedRoleSupplier;
import io.quarkus.spring.security.runtime.interceptor.check.FromBeanRoleSupplier;
import io.quarkus.spring.security.runtime.interceptor.check.PrincipalNameFromParameterObjectSecurityCheck;
import io.quarkus.spring.security.runtime.interceptor.check.PrincipalNameFromParameterSecurityCheck;
import io.quarkus.spring.security.runtime.interceptor.check.SpringSecurityCheckSpec;

/**
 * Creates {@link SecurityCheck} instances from their build-time {@link SpringSecurityCheckSpec descriptions}.
 * The factory is invoked by service actions during the static init.
 */
public final class SpringSecurityCheckFactory {

    private SpringSecurityCheckFactory() {
    }

    public static SecurityCheck create(SpringSecurityCheckSpec spec) {
        return switch (spec) {
            case SpringSecurityCheckSpec.Standard standard -> switch (standard) {
                case PERMIT_ALL -> PermitAllCheck.INSTANCE;
                case DENY_ALL -> DenyAllCheck.INSTANCE;
                case AUTHENTICATED -> AuthenticatedCheck.INSTANCE;
                case ANONYMOUS -> AnonymousCheck.INSTANCE;
            };
            case SpringSecurityCheckSpec.RolesAllowed rolesAllowed -> RolesAllowedCheck
                    .of(rolesAllowed.roles().toArray(String[]::new));
            case SpringSecurityCheckSpec.HasAnyRole hasAnyRole -> new SupplierRolesAllowedCheck(
                    new CombinedRoleSupplier(roleSuppliers(hasAnyRole.roleSuppliers())));
            case SpringSecurityCheckSpec.All all -> new AllDelegatingSecurityCheck(createAll(all.checks()));
            case SpringSecurityCheckSpec.Any any -> new AnyDelegatingSecurityCheck(createAll(any.checks()));
            case SpringSecurityCheckSpec.PrincipalNameFromParameter check -> PrincipalNameFromParameterSecurityCheck
                    .of(check.parameterIndex(), check.checkType());
            case SpringSecurityCheckSpec.PrincipalNameFromParameterObject check -> PrincipalNameFromParameterObjectSecurityCheck
                    .of(check.parameterIndex(), check.expectedParameterClass(), check.stringPropertyAccessorClass(),
                            check.propertyName(), check.checkType());
            case SpringSecurityCheckSpec.GeneratedClass generatedClass -> fromGeneratedClass(generatedClass.className());
        };
    }

    private static List<SecurityCheck> createAll(List<SpringSecurityCheckSpec> specs) {
        List<SecurityCheck> securityChecks = new ArrayList<>(specs.size());
        for (SpringSecurityCheckSpec spec : specs) {
            securityChecks.add(create(spec));
        }
        return securityChecks;
    }

    private static List<Supplier<String[]>> roleSuppliers(List<SpringSecurityCheckSpec.RoleSupplier> specs) {
        List<Supplier<String[]>> suppliers = new ArrayList<>(specs.size());
        for (SpringSecurityCheckSpec.RoleSupplier spec : specs) {
            suppliers.add(switch (spec) {
                case SpringSecurityCheckSpec.StaticRole staticRole -> new Supplier<String[]>() {
                    @Override
                    public String[] get() {
                        return new String[] { staticRole.role() };
                    }
                };
                case SpringSecurityCheckSpec.BeanFieldRole beanFieldRole -> new FromBeanRoleSupplier(
                        loadClass(beanFieldRole.beanClass()), beanFieldRole.fieldName());
            });
        }
        return suppliers;
    }

    private static SecurityCheck fromGeneratedClass(String generatedClassName) {
        try {
            Class<?> type = loadClass(generatedClassName);
            //invoked at static init, no reflection registration required
            Method m = type.getDeclaredMethod("getInstance");
            return (SecurityCheck) m.invoke(null);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static Class<?> loadClass(String className) {
        try {
            return Class.forName(className, false, Thread.currentThread().getContextClassLoader());
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }
}
