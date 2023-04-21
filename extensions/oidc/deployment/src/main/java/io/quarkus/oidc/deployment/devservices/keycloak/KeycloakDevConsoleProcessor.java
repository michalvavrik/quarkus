package io.quarkus.oidc.deployment.devservices.keycloak;

import java.util.Map;
import java.util.Optional;

import io.quarkus.deployment.Capabilities;
import io.quarkus.deployment.IsDevelopment;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.Consume;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.RuntimeConfigSetupCompleteBuildItem;
import io.quarkus.deployment.pkg.builditem.CurateOutcomeBuildItem;
import io.quarkus.devconsole.spi.DevConsoleRouteBuildItem;
import io.quarkus.devconsole.spi.DevConsoleRuntimeTemplateInfoBuildItem;
import io.quarkus.devconsole.spi.DevConsoleTemplateInfoBuildItem;
import io.quarkus.devui.spi.JsonRPCProvidersBuildItem;
import io.quarkus.devui.spi.page.CardPageBuildItem;
import io.quarkus.oidc.deployment.OidcBuildTimeConfig;
import io.quarkus.oidc.deployment.devservices.AbstractDevConsoleProcessor;
import io.quarkus.oidc.deployment.devservices.OidcAuthorizationCodePostHandler;
import io.quarkus.oidc.deployment.devservices.OidcPasswordClientCredHandler;
import io.quarkus.oidc.deployment.devservices.OidcTestServiceHandler;
import io.quarkus.oidc.runtime.devui.OidcDevJsonRpcService;
import io.quarkus.oidc.runtime.devui.OidcDevUiRecorder;

public class KeycloakDevConsoleProcessor extends AbstractDevConsoleProcessor {

    KeycloakBuildTimeConfig keycloakConfig;
    OidcBuildTimeConfig oidcConfig;

    @Record(ExecutionTime.RUNTIME_INIT)
    @BuildStep(onlyIf = IsDevelopment.class)
    @Consume(RuntimeConfigSetupCompleteBuildItem.class)
    public void setConfigProperties(BuildProducer<DevConsoleTemplateInfoBuildItem> devConsoleInfo,
            BuildProducer<DevConsoleRuntimeTemplateInfoBuildItem> devConsoleRuntimeInfo,
            Optional<KeycloakDevServicesConfigBuildItem> configProps,
            BuildProducer<CardPageBuildItem> cardPageProducer,
            OidcDevUiRecorder recorder,
            Capabilities capabilities, CurateOutcomeBuildItem curateOutcomeBuildItem) {
        if (configProps.isPresent() && configProps.get().getConfig().containsKey("keycloak.url")) {
            devConsoleInfo.produce(
                    new DevConsoleTemplateInfoBuildItem("keycloakAdminUrl", configProps.get().getConfig().get("keycloak.url")));
            devConsoleInfo.produce(
                    new DevConsoleTemplateInfoBuildItem("keycloakUsers",
                            configProps.get().getProperties().get("oidc.users")));
            devConsoleInfo.produce(
                    new DevConsoleTemplateInfoBuildItem("keycloakRealms",
                            configProps.get().getProperties().get("keycloak.realms")));

            String realmUrl = configProps.get().getConfig().get("quarkus.oidc.auth-server-url");

            // old DEV UI
            produceDevConsoleTemplateItems(capabilities,
                    devConsoleInfo,
                    devConsoleRuntimeInfo,
                    curateOutcomeBuildItem,
                    "Keycloak",
                    (String) configProps.get().getConfig().get("quarkus.oidc.application-type"),
                    oidcConfig.devui.grant.type.isPresent() ? oidcConfig.devui.grant.type.get().getGrantType()
                            : keycloakConfig.devservices.grant.type.getGrantType(),
                    realmUrl + "/protocol/openid-connect/auth",
                    realmUrl + "/protocol/openid-connect/token",
                    realmUrl + "/protocol/openid-connect/logout",
                    true);

            // new DEV UI
            cardPageProducer.produce(createCardPage(
                    recorder,
                    capabilities,
                    "Keycloak",
                    configProps.get().getConfig().get("quarkus.oidc.application-type"),
                    oidcConfig.devui.grant.type.isPresent() ? oidcConfig.devui.grant.type.get().getGrantType()
                            : keycloakConfig.devservices.grant.type.getGrantType(),
                    realmUrl + "/protocol/openid-connect/auth",
                    realmUrl + "/protocol/openid-connect/token",
                    realmUrl + "/protocol/openid-connect/logout",
                    true
            ));
        }
    }

    @BuildStep(onlyIf = IsDevelopment.class)
    void invokeEndpoint(BuildProducer<DevConsoleRouteBuildItem> devConsoleRoute,
                        BuildProducer<JsonRPCProvidersBuildItem> jsonRPCProvidersProducer,
            Optional<KeycloakDevServicesConfigBuildItem> configProps) {
        if (configProps.isPresent() && configProps.get().getConfig().containsKey("keycloak.url")) {
            @SuppressWarnings("unchecked")
            Map<String, String> users = (Map<String, String>) configProps.get().getProperties().get("oidc.users");
            produceDevConsoleRouteItems(devConsoleRoute,
                    new OidcTestServiceHandler(KeycloakDevServicesProcessor.vertxInstance, oidcConfig.devui.webClientTimeout),
                    new OidcAuthorizationCodePostHandler(KeycloakDevServicesProcessor.vertxInstance,
                            oidcConfig.devui.webClientTimeout,
                            oidcConfig.devui.grantOptions),
                    new OidcPasswordClientCredHandler(KeycloakDevServicesProcessor.vertxInstance,
                            oidcConfig.devui.webClientTimeout, users,
                            oidcConfig.devui.grantOptions));

            // FIXME: different route handler???
            jsonRPCProvidersProducer.produce(new JsonRPCProvidersBuildItem(OidcDevJsonRpcService.class));
        }
    }
}
