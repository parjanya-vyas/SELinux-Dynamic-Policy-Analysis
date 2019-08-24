/*
** client.c -- a stream socket client
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <arpa/inet.h>

#define PORT "5000" // the port client will be connecting to 

#define MAXDATASIZE 1024 // max number of bytes we can get at once

int mysocket(int domain, int type, int protocol);

int myconnect(int sockfd, const struct sockaddr* addr, socklen_t addrlen); 

int mybind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

int rwfm_sockfd;
// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int rwfm_connect()
{
    struct addrinfo hints, *servinfo, *p;
    int rv;
    char s[INET6_ADDRSTRLEN];

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
        fprintf(stderr, "\ngetaddrinfo: %s\n", gai_strerror(rv));
        return -1;
    }

    // loop through all the results and connect to the first we can
    for(p = servinfo; p != NULL; p = p->ai_next) {
        if ((rwfm_sockfd = mysocket(p->ai_family, p->ai_socktype,
                p->ai_protocol)) == -1) {
            perror("client: socket");
            continue;
        }

        int opt_val = 1;
        if(setsockopt(rwfm_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt_val, sizeof(opt_val))<0)
            perror("setsockopt failed:");
#ifdef SO_REUSEPORT
        if(setsockopt(rwfm_sockfd, SOL_SOCKET, SO_REUSEPORT, &opt_val, sizeof(opt_val))<0)
            perror("setsockopt failed:");
#endif

        if (myconnect(rwfm_sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(rwfm_sockfd);
            //perror("client: connect");
            continue;
        }

        break;
    }

    if (p == NULL) {
        fprintf(stderr, "\nclient: failed to connect\n");
        return -2;
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
            s, sizeof s);
    //printf("\nclient: connecting to %s\n", s);

    freeaddrinfo(servinfo); // all done with this structure
    return 1;
}

