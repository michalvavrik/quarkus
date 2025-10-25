package io.quarkus.oidc.token.propagation.common.deployment;

import java.util.List;

import org.jboss.jandex.AnnotationInstance;
import org.jboss.jandex.AnnotationTarget;
import org.jboss.jandex.DotName;
import org.jboss.jandex.MethodInfo;

import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.CombinedIndexBuildItem;
import io.quarkus.oidc.token.propagation.common.AccessToken;

public class OidcTokenPropagationCommonProcessor {

    private static final DotName ACCESS_TOKEN = DotName.createSimple(AccessToken.class.getName());

    @BuildStep
    public List<AccessTokenInstanceBuildItem> collectAccessTokenInstances(CombinedIndexBuildItem index) {
        record ItemBuilder(AnnotationInstance instance) {

            private String toClientName() {
                var value = instance.value("exchangeTokenClient");
                return value == null || value.asString().equals("Default") ? "" : value.asString();
            }

            private boolean toExchangeToken() {
                return instance.value("exchangeTokenClient") != null;
            }

            private MethodInfo methodInfo() {
                if (instance.target().kind() == AnnotationTarget.Kind.METHOD) {
                    return instance.target().asMethod();
                }
                return null;
            }

            private AccessTokenInstanceBuildItem build() {
                return new AccessTokenInstanceBuildItem(toClientName(), toExchangeToken(), instance.target(), methodInfo());
            }
        }
        var accessTokenAnnotations = index.getIndex().getAnnotations(ACCESS_TOKEN);
        return accessTokenAnnotations.stream().map(ItemBuilder::new).map(ItemBuilder::build).toList();
    }

}
