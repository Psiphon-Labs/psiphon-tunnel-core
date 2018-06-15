#include "PsiphonTunnel.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char *read_file(char *filename) {
    char *buffer = NULL;
    size_t size = 0;

    FILE *fp = fopen(filename, "r");

    if (!fp) {
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    size = ftell(fp); 

    rewind(fp);
    buffer = malloc((size + 1) * sizeof(*buffer));

    fread(buffer, size, 1, fp);
    buffer[size] = '\0';

    return buffer;
}

int main(int argc, char *argv[]) {
    
    // load config
    char * const default_config = "psiphon_config";

    char * config = argv[1];

    if (!config) {
        config = default_config;
        printf("Using default config file: %s\n", default_config);
    }

    char *file_contents = read_file(config);
    if (!file_contents) {
        printf("Could not find config file: %s\n", config);
        return 1;
    }

    GoString psiphon_config = {file_contents, strlen(file_contents)};

    // set server list
    GoString serverList = {};

    // set timout
    long long timeout = 10;

    // set network ID
    char * const test_network_id = "TEST";
    GoString network_id = {test_network_id, strlen(test_network_id)};

    // start will return once Psiphon connects or does not connect for timeout seconds
    char *result = Start(psiphon_config, serverList, network_id, timeout);
    Stop();

    // print results
    printf("Result: %s\n", result);

    // cleanup
    free(result);
}

