/* SPDX-License-Identifier: GPL-2.0-only
 * Guest check of SQLite (libsqlite3-0.dll): a file database on D: with a transaction, FTS3 full-text search, an R*Tree
 * query and the JSON functions (the features WebKit's storage code uses). */
#include <stdio.h>
#include <string.h>
#include <sqlite3.h>
#include "deptest.h"

static int one_int(sqlite3 *db, const char *sql, long long *out)
{
    sqlite3_stmt *st = NULL;
    int ok = sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW;
    if (ok) *out = sqlite3_column_int64(st, 0);
    sqlite3_finalize(st);
    return ok;
}

int main(void)
{
    sqlite3 *db = NULL;
    long long v = -1;
    remove("t_sqlite.db");
    printf("SQLite %s\n", sqlite3_libversion());
    CHECK(sqlite3_open("t_sqlite.db", &db) == SQLITE_OK);
    CHECK(sqlite3_exec(db, "PRAGMA journal_mode=DELETE; CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT);"
                           "BEGIN; WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<5000)"
                           " INSERT INTO t(name) SELECT 'row' || x FROM c; COMMIT;", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(one_int(db, "SELECT count(*) FROM t", &v) && v == 5000);
    CHECK(one_int(db, "SELECT id FROM t WHERE name='row4321'", &v) && v == 4321);
    CHECK(sqlite3_exec(db, "CREATE VIRTUAL TABLE doc USING fts3(body);"
                           "INSERT INTO doc VALUES('the quick brown fox'),('lazy dogs sleep'),('quick silver');",
                           NULL, NULL, NULL) == SQLITE_OK);
    CHECK(one_int(db, "SELECT count(*) FROM doc WHERE body MATCH 'quick'", &v) && v == 2);
    CHECK(sqlite3_exec(db, "CREATE VIRTUAL TABLE box USING rtree(id, x0, x1, y0, y1);"
                           "INSERT INTO box VALUES(1,0,10,0,10),(2,5,15,5,15),(3,20,30,20,30);", NULL, NULL, NULL) == SQLITE_OK);
    CHECK(one_int(db, "SELECT count(*) FROM box WHERE x1>=8 AND x0<=12 AND y1>=8 AND y0<=12", &v) && v == 2);
    CHECK(one_int(db, "SELECT json_extract('{\"a\":[1,2,{\"b\":42}]}', '$.a[2].b')", &v) && v == 42);
    sqlite3_close(db);
    CHECK(sqlite3_open_v2("t_sqlite.db", &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);  /* reopen from disk */
    CHECK(one_int(db, "SELECT sum(id) FROM t", &v) && v == 5000LL * 5001 / 2);
    sqlite3_close(db);
    remove("t_sqlite.db");
    return DONE("t_dep_sqlite");
}
