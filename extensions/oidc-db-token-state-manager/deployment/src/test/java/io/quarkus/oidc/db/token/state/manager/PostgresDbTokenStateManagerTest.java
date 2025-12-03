package io.quarkus.oidc.db.token.state.manager;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import jakarta.inject.Inject;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;
import io.smallrye.mutiny.Uni;
import io.vertx.sqlclient.Pool;
import io.vertx.sqlclient.Row;
import io.vertx.sqlclient.RowSet;

public class PostgresDbTokenStateManagerTest extends AbstractDbTokenStateManagerTest {

    @RegisterExtension
    static final QuarkusUnitTest test = createQuarkusUnitTest("quarkus-reactive-pg-client")
            .overrideRuntimeConfigKey("quarkus.oidc.db-token-state-manager.id-token-column-size", "6000");

    @Inject
    Pool pool;

    @Test
    void testIdTokenColumnSize() {
        var rowSet = Uni.createFrom().completionStage(pool
                .preparedQuery(
                        "SELECT column_name, character_maximum_length FROM information_schema.columns WHERE table_name = 'oidc_db_token_state_manager' AND column_name IN ('id_token', 'access_token', 'refresh_token')")
                .execute()
                .toCompletionStage()).await().indefinitely();
        // we configured the id token column size to 6000
        assertEquals(6000, getActualColumnSize(rowSet, "id_token"));
        // expect default size 5000
        assertEquals(5000, getActualColumnSize(rowSet, "access_token"));
        assertEquals(5000, getActualColumnSize(rowSet, "refresh_token"));
    }

    private static int getActualColumnSize(RowSet<Row> rowSet, String columnName) {
        var tokenRow = rowSet.stream().filter(row -> row.getString("column_name").equals(columnName)).findFirst()
                .orElse(null);
        assertNotNull(tokenRow);
        return tokenRow.get(Integer.class, "character_maximum_length");
    }
}
