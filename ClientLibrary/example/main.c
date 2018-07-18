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

    // set client platform
    char * const os = "OSName"; // "Android", "iOS", "Windows", etc.
    char * const os_version = "OSVersion"; // "4.0.4", "10.3", "10.0.10240", etc.
    char * const bundle_identifier = "com.example.exampleClientLibraryApp";
    char * test_client_platform = (char *)malloc(sizeof(char) * (strlen(os) + strlen(os_version) + strlen(bundle_identifier) + 4)); // 4 for 3 underscores and null terminating character

    int n = sprintf(test_client_platform, "%s_%s_%s", os, os_version, bundle_identifier);
    GoString client_platform = {test_client_platform, n};

    // set network ID
    char * const test_network_id = "TEST";
    GoString network_id = {test_network_id, strlen(test_network_id)};

    // set timout
    long long timeout = 60;

    // start will return once Psiphon connects or does not connect for timeout seconds
    char *result = Start(psiphon_config, serverList, client_platform, network_id, timeout);
    Stop();

    // print results
    printf("Result: %s\n", result);

    // The underlying memory of `result` is managed by PsiphonTunnel and will
    // have been freed in Stop.
}

