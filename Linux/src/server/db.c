#include "db.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int callback(void *NotUsed, int argc, char **argv, char **azColName)
{
    int i;
    for (i = 0; i < argc; i++) {
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }
    printf("\n");
    return 0;
}

int select_all_network(sqlite3 *db, int (*f)(void *, int, char **, char **))
{
    char *zErrMsg = 0;
    struct sqlite3_stmt *data;
    char sql[100];
    int rc;

    sprintf(sql, "SELECT * from network");

    int result =
        sqlite3_prepare_v2(db, (const char *)sql, strlen(sql), &data, NULL);

    if (result == SQLITE_OK) {
        if (sqlite3_step(data) == SQLITE_ROW) {
            rc = sqlite3_exec(db, (const char *)&sql, f, 0, &zErrMsg);

            if (rc != SQLITE_OK) {
                fprintf(stderr, "SQL error: %s\n", zErrMsg);
                sqlite3_free(zErrMsg);
                return -1;
            } else {
                fprintf(stdout, "Operation done successfully\n");
            }
        } else {
            printf("No record found!\n");
            return -1;
        }
    } else {
        printf("SQL is not correct!\n");
        return -1;
    }
    return 0;
}

int insert(sqlite3 *db)
{
    int rc;
    char *sql;
    char *zErrMsg = 0;
    /* Create SQL statement */ // Address bits name password
    sql = "INSERT INTO network (Address,bits,name,password) "
          "VALUES ('10.1.1.0', '28', '1111111111', '1111111111' ); ";

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        fprintf(stdout, "Records created successfully\n");
        return 0;
    }
}

void *network_is_exists(sqlite3 *db, char *name, char *password)
{
    printf("name: %s password: %s\n", name, password);
    int rc;
    char *sql;
    struct sqlite3_stmt *data;
    char *return_value;

    sql = "SELECT * from network Where name = ? and password = ?";

    rc = sqlite3_prepare_v2(db, sql, -1, &data, 0);

    if (rc == SQLITE_OK) {

        sqlite3_bind_text(data, 1, name, strlen(name), 0);
        sqlite3_bind_text(data, 2, password, strlen(password), 0);
    } else {

        fprintf(stderr, "Failed to execute statement: %s\n",
                sqlite3_errmsg(db));
    }

    int step = sqlite3_step(data);

    if (step == SQLITE_ROW) {
        return_value = malloc(16);
        strcpy(return_value, sqlite3_column_text(data, 3)); // NAME

    } else {
        printf("No record found!\n");
        sqlite3_finalize(data);
        return NULL;
    }

    sqlite3_finalize(data);
    return return_value;
}

sqlite3 *get_db()
{
    sqlite3 *db;
    int rc;

    rc = sqlite3_open(DB_NAME, &db);

    if (rc) {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        return NULL;
    } else {
        fprintf(stdout, "Opened database successfully\n");
    }
    return db;
}

int create_table(sqlite3 *db)
{

    char *zErrMsg = 0;
    char *sql;
    int rc;
    // address 1 bits 2 id 0 name 3
    sql = "CREATE TABLE IF NOT EXISTS network("
          "id        INTEGER     PRIMARY KEY    AUTOINCREMENT,"
          "Address   CHAR(50)    NOT NULL,"
          "bits      CHAR(50)    NOT NULL,"
          "name      CHAR(50)    NOT NULL UNIQUE,"
          "password  CHAR(50)    NOT NULL);";

    /* Execute SQL statement */
    rc = sqlite3_exec(db, sql, callback, 0, &zErrMsg);

    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", zErrMsg);
        sqlite3_free(zErrMsg);
        return -1;
    } else {
        fprintf(stdout, "Table created successfully\n");
    }
    return 0;
}

int db_close(sqlite3 *db)
{
    return sqlite3_close(db);
    free(db);
}
