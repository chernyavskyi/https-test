#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>

#include <cyassl/ssl.h>
#include <cyassl/test.h>

#define DEFAULT_TIMEOUT 3

static const char msg[] = "GET / HTTP/1.0\r\n\r\n";
static const char msg_200_ok[] = "HTTP/1.1 200 OK\r\n";

static int perform_get_test(int sockfd) {

    if (CyaSSL_Init() < 0)
        err_sys("Unable to init ssl library");

    CYASSL_METHOD *method;
    method = CyaTLSv1_client_method();
    if (method == NULL) {
        err_sys("Unable to get method");
    }

    CYASSL_CTX *ctx = 0;
    ctx = CyaSSL_CTX_new(method);
    if (ctx == NULL) {
        err_sys("Unable to get ctx");
    }

    CyaSSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, 0);
    
    CYASSL* ssl = 0;
    ssl = CyaSSL_new(ctx);
    if (ssl == NULL) {
        err_sys("Unable to get ssl obj");
    }

    if (CyaSSL_set_fd(ssl, sockfd) != SSL_SUCCESS) {
        err_sys("Can't set fd");
    }
    int err, ret;
    ret = CyaSSL_connect(ssl);
    if (ret != SSL_SUCCESS) {
        err = CyaSSL_get_error(ssl, 0);
    }

    if (ret != SSL_SUCCESS) {
        char buffer[CYASSL_MAX_ERROR_SZ];
        printf("err = %d, %s\n", err, CyaSSL_ERR_error_string(err, buffer));
        err_sys("cyaSSL_connect failed");                     
    }
    
    if (CyaSSL_write(ssl, msg, sizeof(msg)) != sizeof(msg)) {
        err_sys("SSL_write failed");
    };

    #define HTTP_BUF_SIZE 500
    char reply[HTTP_BUF_SIZE];
    
    int input = CyaSSL_read(ssl, reply, sizeof(reply));
    if (input > 0) {
        if (!memcmp(reply, msg_200_ok, sizeof(msg_200_ok) - 1)) {
            return 0;
        } else {
            return -1;
        }
    }
    
    return -1;
}

static int connect_to_server(const char *addr, const char *port, int timeout_sec) {
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int err;
    socklen_t err_len = sizeof(err);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = 0;
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

    struct timeval timeout = {timeout_sec, 0};
    
    err = getaddrinfo(addr, port, &hints, &result);
    if (err != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(err));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next) {
        int sockfd = socket(rp->ai_family, rp->ai_socktype,
                        rp->ai_protocol);
        if (sockfd < 0) {
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
                       sizeof(struct timeval)) != 0) {
            goto cont_socket;
        }

        fd_set rset, wset;
        FD_ZERO(&rset);
        FD_SET(sockfd, &rset);
        wset = rset;

        int flags = 0;
        if ((flags = fcntl(sockfd, F_GETFL, 0)) < 0) {
            goto cont_socket;
        }

        if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) < 0) {
            goto cont_socket;
        }

        if ((err = connect(sockfd, rp->ai_addr, rp->ai_addrlen)) != 0) {
            if (errno != EINPROGRESS) {
                goto cont_socket;
            }
        }
        
        if (err == 0) {
            goto done;
        }

        if ((err = select(sockfd + 1, &rset, &wset, NULL, &timeout)) < 0) {
            goto cont_socket;
        }
        if (err == 0) {
            goto err;
        }

        if (FD_ISSET(sockfd, &rset) || FD_ISSET(sockfd, &wset)) {
            if (getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &err, &err_len) < 0)
                goto cont_socket;
        } else {
            goto cont_socket;
        }

        if (fcntl(sockfd, F_SETFL, flags) < 0) {
            close(sockfd);
            goto cont_socket;
        }

    done:
        freeaddrinfo(result);
        return sockfd;

    cont_socket:
        close(sockfd);
    }

err:
    fprintf(stderr, "Could not create a socket\n");
    freeaddrinfo(result);
    return -1;
}

static void usage(const char *name, int exitcode) {
    FILE *out;

    if (exitcode == EXIT_SUCCESS) {
        out = stdout;
    } else {
        out = stderr;
    }

    fprintf(out, "Usage: %s ADDR PORT [TIMEOUT]\n", name);
    fprintf(out, "Send a simple GET request to an HTTPS server at the ADDR:PORT endpoint\n");
    fprintf(out, "and wait [TIMEOUT] seconds until the response received.\n");
    fprintf(out, "Default timeout is 2 seconds\n");
    fprintf(out, "\n\t-h\tDisplay this help and exit\n");
    exit(exitcode);
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "-h")) {
        usage(argv[0], EXIT_SUCCESS);
    } else if (argc != 3 && argc != 4) {
        usage(argv[0], EXIT_FAILURE);
    }

    int timeout;
    if (argc == 4) {
        timeout = atoi(argv[3]);
            
    } else {
        timeout = DEFAULT_TIMEOUT;
    }
    
    int sockfd = connect_to_server(argv[1], argv[2], timeout);
    if (sockfd < 0) {
        fprintf(stderr, "Couldn't connect to server\n");
        return EXIT_FAILURE;
    }

    if (perform_get_test(sockfd) < 0) {
        printf("Status error\n");
        return EXIT_FAILURE;
    } else {
        return EXIT_SUCCESS;
    }
}
