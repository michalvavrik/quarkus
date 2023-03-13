package io.quarkus.vertx.http.deployment;

import static java.lang.Boolean.parseBoolean;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.deployment.Capabilities;
import io.quarkus.deployment.Capability;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.ConfigurationBuildItem;
import io.quarkus.vertx.http.runtime.HttpBuildTimeConfig;
import io.quarkus.vertx.http.runtime.security.AuthenticatedHttpSecurityPolicy;
import io.quarkus.vertx.http.runtime.security.DenySecurityPolicy;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticationMechanismProducer;
import io.quarkus.vertx.http.runtime.security.HttpAuthenticator;
import io.quarkus.vertx.http.runtime.security.HttpAuthorizer;
import io.quarkus.vertx.http.runtime.security.HttpSecurityPolicy;
import io.quarkus.vertx.http.runtime.security.HttpSecurityRecorder;
import io.quarkus.vertx.http.runtime.security.PathMatchingHttpSecurityPolicy;
import io.quarkus.vertx.http.runtime.security.PermitSecurityPolicy;
import io.quarkus.vertx.http.runtime.security.SupplierImpl;

public class HttpSecurityProcessor {

    @BuildStep
    void additionalBeans(Capabilities capabilities, BuildProducer<AdditionalBeanBuildItem> beanProducer) {

        if (capabilities.isPresent(Capability.SECURITY)) {
            // produces basic auth, form auth or mTLS auth mechanism (or none of them)
            // based on runtime configuration properties
            beanProducer.produce(AdditionalBeanBuildItem
                    .unremovableOf(HttpAuthenticationMechanismProducer.class));

            beanProducer.produce(AdditionalBeanBuildItem
                    .unremovableOf(PathMatchingHttpSecurityPolicy.class));

            beanProducer.produce(AdditionalBeanBuildItem.builder().setUnremovable()
                    .addBeanClass(HttpAuthenticator.class).addBeanClass(HttpAuthorizer.class).build());
        }
    }

    @BuildStep(onlyIf = ProactiveAuthDisabled.class)
    @Record(ExecutionTime.RUNTIME_INIT)
    RouteBuildItem prepareFormPostLocationRoute(Capabilities capabilities, HttpSecurityRecorder recorder) {

        if (capabilities.isPresent(Capability.SECURITY)) {
            // add route for form auth mechanism POST location
            // the route is only going to be created if form auth is enabled
            // otherwise the location path is resolved to null and ignored by VertX HTTP processor
            return RouteBuildItem.builder().route(recorder.getFormPostLocation()).handler(recorder.formAuthPostHandler())
                    .build();
        } else {
            return null;
        }
    }

    @BuildStep
    @Record(ExecutionTime.STATIC_INIT)
    void produceAuthFilters(HttpSecurityRecorder recorder, Capabilities capabilities,
            BuildProducer<FilterBuildItem> filterBuildItemBuildProducer) {

        if (capabilities.isPresent(Capability.SECURITY)) {
            filterBuildItemBuildProducer
                    .produce(new FilterBuildItem(
                            recorder.authenticationMechanismHandler(),
                            FilterBuildItem.AUTHENTICATION));

            filterBuildItemBuildProducer
                    .produce(new FilterBuildItem(recorder.permissionCheckHandler(), FilterBuildItem.AUTHORIZATION));
        }
    }

    @BuildStep
    @Record(ExecutionTime.STATIC_INIT)
    public void createPathMatchingHttpSecurityPolicies(Capabilities capabilities,
            List<HttpSecurityPolicyBuildItem> additionalPolicies, HttpSecurityRecorder recorder) {

        if (capabilities.isPresent(Capability.SECURITY)) {
            Map<String, Supplier<HttpSecurityPolicy>> policyMap = new HashMap<>();
            policyMap.put("deny", new SupplierImpl<>(new DenySecurityPolicy()));
            policyMap.put("permit", new SupplierImpl<>(new PermitSecurityPolicy()));
            policyMap.put("authenticated", new SupplierImpl<>(new AuthenticatedHttpSecurityPolicy()));

            for (HttpSecurityPolicyBuildItem additionalPolicy : additionalPolicies) {
                final String policyName = additionalPolicy.getName();
                if (policyMap.containsKey(policyName)) {
                    throw new RuntimeException("Multiple HTTP security policies defined with name " + policyName);
                }
                policyMap.put(policyName, additionalPolicy.getPolicySupplier());
            }

            recorder.addPathMatchingPolicies(policyMap);
        }
    }

    @BuildStep
    void securityInformation(
            Capabilities capabilities,
            ConfigurationBuildItem configurationBuildItem,
            BuildProducer<SecurityInformationBuildItem> securityInformationProducer) {

        if (capabilities.isPresent(Capability.SECURITY)) {
            // security information may only be generated if config properties that configures
            // authentication mechanism are present at build time
            var properties = configurationBuildItem.getReadResult().getAllBuildTimeValues();
            var basicAuthConfigProp = properties.get("quarkus.http.auth.basic");
            final boolean basicAuthExplicitlyEnabled = parseBoolean(basicAuthConfigProp);

            final boolean basicAuthMechanismPresent;
            if (basicAuthExplicitlyEnabled) {
                basicAuthMechanismPresent = true;
            } else {
                // default bean path
                final boolean basicAuthNotExplicitlyDisabled = basicAuthConfigProp == null;
                final boolean formAuthDisabled = parseBoolean(properties.get("quarkus.http.auth.form.enabled"));
                var sslClientAuthConfigProp = properties.get("quarkus.http.ssl.client-auth");
                final boolean mTLSAuthDisabled = sslClientAuthConfigProp == null || "NONE".equals(sslClientAuthConfigProp);
                basicAuthMechanismPresent = basicAuthNotExplicitlyDisabled && formAuthDisabled && mTLSAuthDisabled;
            }

            if (basicAuthMechanismPresent) {
                securityInformationProducer.produce(SecurityInformationBuildItem.BASIC());
            }
        }
    }

    static final class ProactiveAuthDisabled implements BooleanSupplier {

        private final boolean proactiveAuthDisabled;

        ProactiveAuthDisabled(HttpBuildTimeConfig httpBuildTimeConfig) {
            this.proactiveAuthDisabled = !httpBuildTimeConfig.proactiveAuth;
        }

        @Override
        public boolean getAsBoolean() {
            return proactiveAuthDisabled;
        }
    }
}
