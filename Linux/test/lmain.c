#include <assert.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <pthread.h>
#include "../include/rxi_log.h"

pthread_mutex_t MUTEX_LOG;
void log_lock(bool lock, void *udata);

int main(int argc, char *argv[])
{
	time_t t = time(NULL);
	struct tm *tm = localtime(&t);
	char date[64];
	assert(strftime(date, sizeof(date), "%c", tm));
	printf("%s\n", date);
	char file_name[68] = "VLN_Log_";
	strcat(file_name, date);

	pthread_mutex_init(&MUTEX_LOG, NULL);
	log_set_lock(log_lock, &MUTEX_LOG);

	FILE *f = fopen(file_name, "w");
	int res = log_add_fp(f, 0);
	printf("%d\n", res);
	log_set_quiet(false);
	log_trace("Hello %s", "world1");
	log_debug("Hello %s", "world2");
	printf("%s\n", log_level_string(3));

	pthread_mutex_destroy(&MUTEX_LOG);
}

void log_lock(bool lock, void *udata)
{
	pthread_mutex_t *LOCK = (pthread_mutex_t *)(udata);
	if (lock)
		pthread_mutex_lock(LOCK);
	else
		pthread_mutex_unlock(LOCK);
}