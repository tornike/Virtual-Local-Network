
#include <libconfig.h>
#include <stdlib.h>
#include <vln_default_config.h>

int main()
{
    config_t cfg;
    config_setting_t *setting;

    config_init(&cfg);

    /* Read the file. If there is an error, report it and exit. */
    if (!config_read_file(&cfg, VLN_CONFIG_FILE)) {
        fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
                config_error_line(&cfg), config_error_text(&cfg));
        config_destroy(&cfg);
        return (EXIT_FAILURE);
    }

    /* Output a list of all servers */
    setting = config_lookup(&cfg, "servers");
    if (setting != NULL) {
        int count = config_setting_length(setting);
        int i;

        printf("%-10s  %-10s   %-10s  %s\n", "NAME", "ADDRESS", "BIND_IP",
               "BIND_PORT");

        for (i = 0; i < count; ++i) {
            config_setting_t *server = config_setting_get_elem(setting, i);

            /* Only output the record if all of the expected fields are present.
             */
            const char *name, *address, *bind_ip, *bind_port;

            if (!(config_setting_lookup_string(server, "name", &name) &&
                  config_setting_lookup_string(server, "address", &address) &&
                  config_setting_lookup_string(server, "bind_ip", &bind_ip) &&
                  config_setting_lookup_string(server, "bind_port",
                                               &bind_port)))
                continue;

            printf("%-10s  %-10s  %-10s  %-10s\n", name, address, bind_ip,
                   bind_port);
        }
        putchar('\n');
    }

    config_destroy(&cfg);
    return (EXIT_SUCCESS);
}