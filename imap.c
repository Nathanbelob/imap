#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1
#define PORT "993"
#define HOST "imap.gmail.com"

int hname_to_ip(const char *, const char *);
SSL_CTX *InitCTX(void);
void ShowCerts(SSL *);

int main()
{
    SSL_CTX *ctx;
    int server = 0;
    SSL *ssl;
    char buf[1024];
    char acClientRequest[1024] = {0};
    char acClientRequest2[1024] = {0};
    char acClientRequest3[1024] = {0};
    char acClientRequest4[1024] = {0};
    char acClientRequest5[1024] = {0};
    char acClientRequest6[1024] = {0};
    int bytes = 0;
    const char *hostname, *portnum;

    hostname = HOST;
    portnum = PORT;

    SSL_library_init();

    ctx = InitCTX();
    server = hname_to_ip(hostname, portnum);
    ssl = SSL_new(ctx);           // create new SSL connection state ∗/
    SSL_set_fd(ssl, server);      // attach the socket deor ∗/
    if (SSL_connect(ssl) == FAIL) {// perform the connection ∗/
        ERR_print_errors_fp(stderr);
    }
    else
    {
        char acPassword[16] = {0};
        //todo list, select "inbox", list, fetch,decode, logout
       
        printf("\n\nEnter the Password : ");
        scanf("%[^\n]s", acPassword);        

        sprintf(acClientRequest, "Aa login seminariosvi@gmail.com %s\r\n", acPassword); // construct reply ∗/


        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);                                           // get any certs ∗/
        SSL_write(ssl, acClientRequest, strlen(acClientRequest)); // encrypt & send message ∗/
        bytes = SSL_read(ssl, buf, sizeof(buf));                  // get reply & decrypt ∗/
        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);

        sprintf(acClientRequest2, "Bb list \"\" \"*\"\r\n"); // construct reply ∗/
        SSL_write(ssl, acClientRequest2, strlen(acClientRequest2)); // encrypt & send message ∗/
        bytes = SSL_read(ssl, buf, sizeof(buf));                  // get reply & decrypt ∗/
        buf[bytes] = 0;
        printf("Received2: \"%s\"\n", buf);


        sprintf(acClientRequest3, "Cc select \"INBOX\"\r\n"); // construct reply ∗/
        SSL_write(ssl, acClientRequest3, strlen(acClientRequest3)); // encrypt & send message ∗/
        bytes = SSL_read(ssl, buf, sizeof(buf));                  // get reply & decrypt ∗/
        buf[bytes] = 0;
        printf("Received3: \"%s\"\n", buf);

        
        sprintf(acClientRequest4, "Dd UID SEARCH FROM \"Claudio Correa\"\r\n"); // construct reply ∗/
        SSL_write(ssl, acClientRequest4, strlen(acClientRequest4)); // encrypt & send message ∗/
        bytes = SSL_read(ssl, buf, sizeof(buf));                  // get reply & decrypt ∗/
        buf[bytes] = 0;
        printf("Received4: \"%s\"\n", buf);

        sprintf(acClientRequest5, "Ee UID FETCH 42 BODY\r\n"); // construct reply ∗/
        SSL_write(ssl, acClientRequest5, strlen(acClientRequest5)); // encrypt & send message ∗/
        bytes = SSL_read(ssl, buf, sizeof(buf));                  // get reply & decrypt ∗/
        buf[bytes] = 0;
        printf("Received5: \"%s\"\n", buf);

        sprintf(acClientRequest6, "Ee UID FETCH 42 BODY\r\n"); // construct reply ∗/
        SSL_write(ssl, acClientRequest6, strlen(acClientRequest6)); // encrypt & send message ∗/
        bytes = SSL_read(ssl, buf, sizeof(buf));                  // get reply & decrypt ∗/
        buf[bytes] = 0;
        printf("Received5: \"%s\"\n", buf);

        SSL_free(ssl); // release connection state ∗/

    }
    close(server);     // close socket ∗/
    SSL_CTX_free(ctx); // release context ∗/
    return 0;
}

int hname_to_ip(const char *hostname, const char *port) {
    struct addrinfo hints, *srvinfo, *p;
    char addrstr[128];
    int sd = 0;
    void *ptr;

    bzero(&hints, sizeof(hints)); // memset(&hints, 0, sizeof(hints));
    bzero(addrstr, sizeof(addrstr));

    hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_CANONNAME;

    if (getaddrinfo(hostname, port, &hints, &srvinfo) != 0) {
        perror("getaddrinfo failed");
        return(EXIT_FAILURE);
    }

    // loop through all the results and connect to the first we can
    for (p = srvinfo; p != NULL; p = p->ai_next) {
        // inet_ntop(p−>ai_family, p−>ai_addr−>sa_data, addrstr, sizeof(addrstr));
        switch (p->ai_family) {
            case AF_INET:
                ptr = &((struct sockaddr_in *) p->ai_addr)->sin_addr;
            break;
            case AF_INET6:
                ptr = &((struct sockaddr_in6 *) p->ai_addr)->sin6_addr;
            break;
        }

        inet_ntop(p->ai_family, ptr, addrstr, sizeof(addrstr));
        if (p->ai_canonname != '\0') {
            // puts(hostname);
            printf("\nIPv%d address: %s (%s)\n", p->ai_family == PF_INET6 ? 6 : 4, addrstr, p->ai_canonname);
        }

        if ((sd = socket(srvinfo->ai_family, srvinfo->ai_socktype, srvinfo->ai_protocol)) < 0) {
            perror("socket failed");
            continue;
        }
        ///∗ Connect does the bind for us ∗/
        if (connect(sd, srvinfo->ai_addr, srvinfo->ai_addrlen) < 0) {
            perror("connect failed");
            continue;
        } else {
            break; // Connected succesfully!
        }
    }

    ///∗ Free answers after use ∗/
    freeaddrinfo(srvinfo); // all done with this structure

    if (p == NULL) {
        // The loop wasn't able to connect to the server
        fprintf(stderr, "Couldn't connect to the hostname\n.");
        exit(EXIT_FAILURE);
    } else {
        return(sd);
    }
 }

SSL_CTX *InitCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();     // Load cryptos, et.al. ∗/
    SSL_load_error_strings();         // Bring in and register error messages ∗/
    method = TLS_client_method(); // Create new client−method instance ∗/
    ctx = SSL_CTX_new(method);        // Create new context ∗/
    if (ctx == NULL)
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return (ctx);
}
void ShowCerts(SSL *ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); // get the server's certificate ∗/
    if (cert != NULL)
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line); // free the malloc'ed string ∗/
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);      // free the malloc'ed string ∗/
        X509_free(cert); // free the malloc'ed certificate copy ∗/
    }
    else
    {
        printf("Info: No client certificates configured.\n");
    }
    return;
}