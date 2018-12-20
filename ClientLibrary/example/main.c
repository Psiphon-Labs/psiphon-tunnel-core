#include "libpsiphontunnel.h"
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

    char *psiphon_config = read_file(config);
    if (!psiphon_config) {
        printf("Could not find config file: %s\n", config);
        return 1;
    }

    // set server list
    char *server_list = "";

    // set client platform
    char * const os = "OSName"; // "Android", "iOS", "Windows", etc.
    char * const os_version = "OSVersion"; // "4.0.4", "10.3", "10.0.10240", etc.
    char * const bundle_identifier = "com.example.exampleClientLibraryApp";
    char * client_platform = (char *)malloc(sizeof(char) * (strlen(os) + strlen(os_version) + strlen(bundle_identifier) + 4)); // 4 for 3 underscores and null terminating character

    int n = sprintf(client_platform, "%s_%s_%s", os, os_version, bundle_identifier);

    // set network ID
    char * const network_id = "TEST";

    // set timeout
    int32_t timeout = 60;

    struct Parameters params;
    params.sizeofStruct = sizeof(struct Parameters);
    params.dataRootDirectory = ".";
    params.clientPlatform = client_platform;
    params.networkID = network_id;
    params.establishTunnelTimeoutSeconds = &timeout;

    // connect 5 times
    for (int i = 0; i < 5; i++) {
        // start will return once Psiphon connects or does not connect for timeout seconds
        char *result = PsiphonTunnelStart(psiphon_config, server_list, &params);

        // print results
        printf("Result: %s\n", result);

        // The underlying memory of `result` is managed by PsiphonTunnel and is freed in Stop
        PsiphonTunnelStop();
    }

    free(client_platform);
    client_platform = NULL;
    free(psiphon_config);
    psiphon_config = NULL;
}

