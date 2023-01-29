package io.quarkus.security.runtime;

import static io.quarkus.security.runtime.QuarkusSecurityCheckConfigBuilder.transformToKey;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.Permission;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.spi.ConfigProviderResolver;

import io.quarkus.runtime.RuntimeValue;
import io.quarkus.runtime.annotations.Recorder;
import io.quarkus.security.identity.SecurityIdentity;
import io.quarkus.security.runtime.interceptor.SecurityCheckStorageBuilder;
import io.quarkus.security.runtime.interceptor.check.AuthenticatedCheck;
import io.quarkus.security.runtime.interceptor.check.DenyAllCheck;
import io.quarkus.security.runtime.interceptor.check.PermissionSecurityCheck;
import io.quarkus.security.runtime.interceptor.check.PermitAllCheck;
import io.quarkus.security.runtime.interceptor.check.RolesAllowedCheck;
import io.quarkus.security.runtime.interceptor.check.SupplierRolesAllowedCheck;
import io.quarkus.security.spi.runtime.MethodDescription;
import io.quarkus.security.spi.runtime.SecurityCheck;
import io.quarkus.security.spi.runtime.SecurityCheckStorage;
import io.smallrye.config.Expressions;
import io.smallrye.mutiny.Uni;

@Recorder
public class SecurityCheckRecorder {

    private static volatile SecurityCheckStorage storage;

    public static SecurityCheckStorage getStorage() {
        return storage;
    }

    public SecurityCheck denyAll() {
        return DenyAllCheck.INSTANCE;
    }

    public SecurityCheck permitAll() {
        return PermitAllCheck.INSTANCE;
    }

    public SecurityCheck rolesAllowed(String... roles) {
        return RolesAllowedCheck.of(roles);
    }

    public Map.Entry<SecurityCheck, Runnable> rolesAllowedSupplier(String[] allowedRoles, int[] configExpIndexes,
            int[] configKeys) {
        addExpressionsAsConfigProperties(allowedRoles, configExpIndexes, configKeys);

        final var check = new SupplierRolesAllowedCheck(
                resolveConfigExpressions(allowedRoles, configExpIndexes, configKeys));
        return Map.entry(check, new Runnable() {
            @Override
            public void run() {
                // resolve config expressions
                check.resolveAllowedRoles();
            }
        });
    }

    private static void addExpressionsAsConfigProperties(String[] annotationValue, int[] configExpIndexes, int[] configKeys) {
        // here we add generated keys and values with the property expressions to the config source,
        // the config source will be registered with the Config system,
        // and we get all features available from Config
        for (int i = 0; i < configExpIndexes.length; i++) {
            QuarkusSecurityCheckConfigBuilder.addProperty(configKeys[i], annotationValue[configExpIndexes[i]]);
        }
    }

    private static Supplier<String[]> resolveConfigExpressions(String[] annotationValue, int[] configExpIndexes,
            int[] configKeys) {

        final String[] result = Arrays.copyOf(annotationValue, annotationValue.length);
        return new Supplier<String[]>() {
            @Override
            public String[] get() {
                final var config = ConfigProviderResolver.instance().getConfig(Thread.currentThread().getContextClassLoader());
                if (config.getOptionalValue(Config.PROPERTY_EXPRESSIONS_ENABLED, Boolean.class).orElse(Boolean.TRUE)
                        && Expressions.isEnabled()) {
                    // property expressions are enabled
                    for (int i = 0; i < configExpIndexes.length; i++) {
                        // resolve configuration expressions specified as value of a security annotation
                        result[configExpIndexes[i]] = config.getValue(transformToKey(configKeys[i]), String.class);
                    }
                }
                return result;
            }
        };
    }

    public SecurityCheck authenticated() {
        return AuthenticatedCheck.INSTANCE;
    }

    public RuntimeValue<SecurityCheckStorageBuilder> newBuilder() {
        return new RuntimeValue<>(new SecurityCheckStorageBuilder());
    }

    public void addMethod(RuntimeValue<SecurityCheckStorageBuilder> builder, String className,
            String methodName,
            String[] parameterTypes,
            SecurityCheck securityCheck) {
        builder.getValue().registerCheck(className, methodName, parameterTypes, securityCheck);
    }

    public void create(RuntimeValue<SecurityCheckStorageBuilder> builder) {
        storage = builder.getValue().create();
    }

    public void resolveSecurityCheckConfigExpressions(List<Runnable> securityChecksWithConfigExpResolvers) {
        for (Runnable resolver : securityChecksWithConfigExpResolvers) {
            // resolve config expression
            resolver.run();
        }
    }

    private static void createPermission() {
        // runtime value - permission
        // create permission with 'name' and optionally 'actions'
        // accept class

        // computed permission (should this include config expression?)
        // different case - also accept
    }

    public Map.Entry<SecurityCheck, Runnable> permissionsAllowedSupplier(String[][] allowedPermissionsGroups,
                                                                         int[][] configExpIndexes, int[][] configKeys,
                                                                         Class<? extends Permission> permissionClass) {
        return null;
    }

    public Map.Entry<SecurityCheck, Runnable> permissionsAllowedSupplier(String[] allowedPermissions, int[] configExpIndexes,
            int[] configKeys, Class<? extends Permission> permissionClass) {

        addExpressionsAsConfigProperties(allowedPermissions, configExpIndexes, configKeys);
        var permissionStrSupplier = resolveConfigExpressions(allowedPermissions, configExpIndexes, configKeys);
        final var check = new SecurityCheck() {

            private SecurityCheck delegate;

            @Override
            public void apply(SecurityIdentity identity, Method method, Object[] parameters) {
                delegate.apply(identity, method, parameters);
            }

            @Override
            public void apply(SecurityIdentity identity, MethodDescription methodDescription, Object[] parameters) {
                delegate.apply(identity, methodDescription, parameters);
            }

            @Override
            public Uni<?> nonBlockingApply(SecurityIdentity identity, Method method, Object[] parameters) {
                return delegate.nonBlockingApply(identity, method, parameters);
            }

            @Override
            public Uni<?> nonBlockingApply(SecurityIdentity identity, MethodDescription methodDescription,
                    Object[] parameters) {
                return delegate.nonBlockingApply(identity, methodDescription, parameters);
            }
        };
        Runnable delegateCreator;
        if (allowedPermissions.length == 1) {
            // single permission
            delegateCreator = new Runnable() {
                @Override
                public void run() {
                    // FIXME: parse actions and permissions
                    // resolve config expressions
                    check.delegate = PermissionSecurityCheck.of(createPermissionInstance(permissionClass), null);
                }
            };
        } else {
            // multiple permissions
            delegateCreator = new Runnable() {
                @Override
                public void run() {
                    // FIXME: parse actions and permissions
                    // resolve config expressions
                    final Permission[] permissions = new Permission[allowedPermissions.length];
                    for (int i = 0; i < permissionStrSupplier.get().length; i++) {
                        permissions[i] = createPermissionInstance(permissionClass);
                    }
                    check.delegate = PermissionSecurityCheck.of(permissions, null);
                }
            };
        }

        // delegate must be created during runtime when config expressions are resolved
        return Map.entry(check, delegateCreator);
    }

    private static Permission createPermissionInstance(Class<? extends Permission> permissionClass) {
        try {
            // FIXME validate if there are actions there must be actions constructor (or not??? must not!)
            // FIXME this does not respect multiple constructor options
            return permissionClass.getConstructor().newInstance();
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            throw new RuntimeException(String.format("Failed to create '%s'", permissionClass), e);
        }
    }
}
