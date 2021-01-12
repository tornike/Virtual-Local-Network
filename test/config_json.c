
#include <errno.h>
#include <json-c/json.h>
#include <stdio.h>
#include <string.h>
#include <vln_default_config.h>

int main()
{
    char buffer[4096];
    struct json_object *parsed_json;
    struct json_object *servers;
    struct json_object *clients;

    struct json_object *name;
    struct json_object *address;
    struct json_object *bind_ip;
    struct json_object *bind_port;

    FILE *fp =
        fopen(VLN_CONFIG_FILE, "r"); // not valid anymore. should be json file
    printf("%lu %s\n", fread(buffer, 4096, 1, fp), strerror(errno));
    fclose(fp);

    parsed_json = json_tokener_parse(buffer);

    printf("servers: %d\n",
           json_object_object_get_ex(parsed_json, "servers", &servers));
    printf("clients: %d\n",
           json_object_object_get_ex(parsed_json, "clients", &clients));

    struct json_object *s1 = json_object_array_get_idx(servers, 0);
    struct json_object *c1 = json_object_array_get_idx(clients, 0);

    printf("client addr %llu\n", (long long)c1);

    json_object_object_get_ex(s1, "name", &name);
    json_object_object_get_ex(s1, "address", &address);
    json_object_object_get_ex(s1, "bind_ip", &bind_ip);
    json_object_object_get_ex(s1, "bind_port", &bind_port);

    printf("%s\n", json_object_get_string(name));
    printf("%s\n", json_object_get_string(address));
    printf("%s\n", json_object_get_string(bind_ip));
    printf("%s\n", json_object_get_string(bind_port));

    return 0;
}