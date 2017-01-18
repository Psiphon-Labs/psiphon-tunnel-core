/*
 * Copyright (c) 2016, Psiphon Inc.
 * All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "LookupIPv6.h"

#include <arpa/inet.h>
#include <err.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>

char *getIPv6ForIPv4(const char *ipv4_str) {
    char *ipv6_str = NULL;
    struct addrinfo hints, *res, *res0;
    int error;
    
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_DEFAULT;
    error = getaddrinfo(ipv4_str, NULL, &hints, &res0);
    if (error) {
        /* NOTREACHED */
        return NULL;
    }

    for (res = res0; res; res = res->ai_next) {
        if (res->ai_family == AF_INET6) {
            struct sockaddr_in6 *sockaddr = (struct sockaddr_in6*)res->ai_addr;
            ipv6_str = (char *)malloc(sizeof(char)*(INET6_ADDRSTRLEN)); // INET6_ADDRSTRLEN includes null terminating character
            inet_ntop(AF_INET6, &(sockaddr->sin6_addr), ipv6_str, INET6_ADDRSTRLEN);
            break;
        }
    }
    
    freeaddrinfo(res0);
    return ipv6_str;
}
