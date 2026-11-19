package io.quarkus.oidc.db.token.state.manager;

import static io.quarkus.deployment.Capability.REACTIVE_DB2_CLIENT;
import static io.quarkus.deployment.Capability.REACTIVE_MSSQL_CLIENT;
import static io.quarkus.deployment.Capability.REACTIVE_MYSQL_CLIENT;
import static io.quarkus.deployment.Capability.REACTIVE_ORACLE_CLIENT;
import static io.quarkus.deployment.Capability.REACTIVE_PG_CLIENT;
import static java.lang.String.format;

import java.util.function.BooleanSupplier;

import jakarta.inject.Singleton;

import io.quarkus.arc.deployment.SyntheticBeanBuildItem;
import io.quarkus.builder.item.SimpleBuildItem;
import io.quarkus.core.Phase;
import io.quarkus.core.deployment.service.ServiceRegistrar;
import io.quarkus.deployment.Capabilities;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.BuildSteps;
import io.quarkus.deployment.builditem.ServiceStartBuildItem;
import io.quarkus.oidc.TokenStateManager;
import io.quarkus.oidc.db.token.state.manager.runtime.OidcDbTokenStateManager;
import io.quarkus.oidc.db.token.state.manager.runtime.OidcDbTokenStateManagerInitializer;
import io.quarkus.oidc.db.token.state.manager.runtime.OidcDbTokenStateManagerInitializer.SupportedReactiveSqlClient;
import io.quarkus.oidc.db.token.state.manager.runtime.OidcDbTokenStateManagerRunTimeConfig;
import io.quarkus.runtime.configuration.ConfigurationException;
import io.vertx.core.Vertx;
import io.vertx.sqlclient.Pool;

@BuildSteps(onlyIf = OidcDbTokenStateManagerProcessor.OidcDbTokenStateManagerEnabled.class)
public class OidcDbTokenStateManagerProcessor {

    private static final String[] SUPPORTED_REACTIVE_CLIENTS = new String[] { REACTIVE_PG_CLIENT, REACTIVE_MYSQL_CLIENT,
            REACTIVE_MSSQL_CLIENT, REACTIVE_DB2_CLIENT, REACTIVE_ORACLE_CLIENT };

    @BuildStep
    SyntheticBeanBuildItem produceDbTokenStateManagerBean(ReactiveSqlClientBuildItem sqlClientBuildItem,
            ServiceRegistrar serviceRegistrar) {
        final String[] queryParamPlaceholders;
        switch (sqlClientBuildItem.reactiveClient) {
            case REACTIVE_PG_CLIENT:
                queryParamPlaceholders = new String[] { "$1", "$2", "$3", "$4", "$5", "$6", "$7" };
                break;
            case REACTIVE_MSSQL_CLIENT:
                queryParamPlaceholders = new String[] { "@p1", "@p2", "@p3", "@p4", "@p5", "@p6", "@p7" };
                break;
            case REACTIVE_MYSQL_CLIENT:
            case REACTIVE_DB2_CLIENT:
            case REACTIVE_ORACLE_CLIENT:
                queryParamPlaceholders = new String[] { "?", "?", "?", "?", "?", "?", "?" };
                break;
            default:
                throw new RuntimeException("Unknown Reactive Sql Client " + sqlClientBuildItem.reactiveClient);
        }
        String deleteStatement = format("DELETE FROM oidc_db_token_state_manager WHERE id = %s", queryParamPlaceholders[0]);
        String getQuery = format(
                "SELECT id_token, access_token, refresh_token, access_token_expires_in, access_token_scope FROM oidc_db_token_state_manager WHERE "
                        +
                        "id = %s",
                queryParamPlaceholders[0]);
        String insertStatement = format("INSERT INTO oidc_db_token_state_manager (id_token, access_token, refresh_token," +
                " access_token_expires_in, access_token_scope, expires_in, id) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                queryParamPlaceholders[0],
                queryParamPlaceholders[1],
                queryParamPlaceholders[2], queryParamPlaceholders[3], queryParamPlaceholders[4], queryParamPlaceholders[5],
                queryParamPlaceholders[6]);
        serviceRegistrar
                .forService(OidcDbTokenStateManager.class)
                .atPhase(Phase.DATA)
                .consumeAll(Pool.class)
                .onStart((ctx, poolMap) -> new OidcDbTokenStateManager(insertStatement, deleteStatement, getQuery,
                        OidcDbTokenStateManagerInitializer.getDefaultPool(poolMap)));
        return SyntheticBeanBuildItem
                .configure(OidcDbTokenStateManager.class)
                .alternative(true)
                .priority(1)
                .addType(TokenStateManager.class)
                .unremovable()
                .scope(Singleton.class)
                .serviceValue(OidcDbTokenStateManager.class)
                .done();
    }

    @BuildStep
    ReactiveSqlClientBuildItem validateReactiveSqlClient(
            Capabilities capabilities) {
        ReactiveSqlClientBuildItem sqlClientDbTable = null;
        for (String reactiveClient : SUPPORTED_REACTIVE_CLIENTS) {
            if (capabilities.isPresent(reactiveClient)) {
                if (sqlClientDbTable == null) {
                    sqlClientDbTable = new ReactiveSqlClientBuildItem(reactiveClient);
                } else {
                    throw new ConfigurationException("The OpenID Connect Database Token State Manager extension is "
                            + "only supported when exactly one Reactive SQL Client extension is present.");
                }
            }
        }
        if (sqlClientDbTable == null) {
            throw new ConfigurationException(
                    "The OpenID Connect Database Token State Manager extension requires Reactive SQL Client extension. "
                            + "Please refer to the https://quarkus.io/guides/reactive-sql-clients for more information.");
        }
        return sqlClientDbTable;
    }

    @BuildStep
    void createDbTokenStateInitializerProps(ReactiveSqlClientBuildItem sqlClientBuildItem, ServiceRegistrar reg) {
        var supportedReactiveSqlClient = switch (sqlClientBuildItem.reactiveClient) {
            case REACTIVE_PG_CLIENT -> SupportedReactiveSqlClient.POSTGRESQL;
            case REACTIVE_MYSQL_CLIENT -> SupportedReactiveSqlClient.MYSQL;
            case REACTIVE_MSSQL_CLIENT -> SupportedReactiveSqlClient.MSSQL;
            case REACTIVE_DB2_CLIENT -> SupportedReactiveSqlClient.DB2;
            case REACTIVE_ORACLE_CLIENT -> SupportedReactiveSqlClient.ORACLE;
            default -> throw new ConfigurationException("Unknown Reactive Sql Client " + sqlClientBuildItem.reactiveClient);
        };
        reg
                .forService("io.quarkus.oidc.db.token.state.manager.initializer")
                .afterBuildItem(ServiceStartBuildItem.class)
                // TODO: actually it would be ideal to schedule this between startup event and io.quarkus.vertx.http.deployment.VertxHttpProcessor.openSocket
                //      but there doesn't seem to be a way for now
                .before("io.quarkus.arc.startup-event")
                .require(OidcDbTokenStateManagerRunTimeConfig.class)
                .require(Vertx.class)
                .consumeAll(Pool.class)
                .onStart((ctx, config, vertx, poolMap) -> {
                    long taskId = OidcDbTokenStateManagerInitializer.initialize(supportedReactiveSqlClient, config, vertx,
                            OidcDbTokenStateManagerInitializer.getDefaultPool(poolMap));
                    ctx.onStop(() -> vertx.cancelTimer(taskId));
                });
    }

    static final class OidcDbTokenStateManagerEnabled implements BooleanSupplier {

        OidcDbTokenStateManagerBuildTimeConfig config;

        @Override
        public boolean getAsBoolean() {
            return config.enabled();
        }
    }

    static final class ReactiveSqlClientBuildItem extends SimpleBuildItem {

        private final String reactiveClient;

        private ReactiveSqlClientBuildItem(String reactiveClient) {
            this.reactiveClient = reactiveClient;
        }
    }

}
