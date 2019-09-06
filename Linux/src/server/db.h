#ifndef __VLN_DB__
#define __VLN_DB__

#include <sqlite3.h>

#define DB_NAME "vln.db"
#define NAME_SIZE 17

sqlite3 *get_db();

int select_all_network(sqlite3 *db, int (*f)(void *, int, char **, char **));

void *network_is_exists(sqlite3 *db, char *name, char *password);

sqlite3 *get_db();

int create_table(sqlite3 *db);

int db_close(sqlite3 *db);

int insert_new_network(sqlite3 *db, char *address, char *bits, char *name,
                       char *password);

#endif