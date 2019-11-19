#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL -1

int OpenConnection(const char *, const char *);
SSL_CTX *InitCTX(void);
void ShowCerts(SSL *);

int main(int count, char *strings[])
{
    SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    char acClientRequest[1024] = {0};
    int bytes;
    const char *hostname, *portnum;

    if (count != 3)
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();
    hostname = strings[1];
    portnum = strings[2];

    ctx = InitCTX();
    server = OpenConnection(hostname, portnum);
    ssl = SSL_new(ctx);           // create new SSL connection state ∗/
    SSL_set_fd(ssl, server);      // attach the socket deor ∗/
    if (SSL_connect(ssl) == FAIL) // perform the connection ∗/
        ERR_print_errors_fp(stderr);
    else
    {
        char acUsername[16] = {0};
        char acPassword[16] = {0};
        const char *cpRequestMessage = "<Body>\
 <UserName>%s<UserName>\
 <Password>%s<Password>\
 <\Body>";

        printf("Enter the User Name : ");
        scanf("%s", acUsername);

        printf("\n\nEnter the Password : ");
        scanf("%s", acPassword);

        sprintf(acClientRequest, cpRequestMessage, acUsername, acPassword); // construct reply ∗/

        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);                                           // get any certs ∗/
        SSL_write(ssl, acClientRequest, strlen(acClientRequest)); // encrypt & send message ∗/
        bytes = SSL_read(ssl, buf, sizeof(buf));                  // get reply & decrypt ∗/
        buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);
        SSL_free(ssl); // release connection state ∗/
    }
    close(server);     // close socket ∗/
    SSL_CTX_free(ctx); // release context ∗/
    return 0;
}

int OpenConnection(const char *hostname, const char *port)
{
     struct addrinfo hints, *srvinfo, *p;
  char addrstr[128];
  int errcode = 0;
  int sd = 0;
  void *ptr;

  bzero(&hints, sizeof(hints));
  bzero(addrstr, sizeof(addrstr));

  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags |= AI_CANONNAME;
  getaddrinfo (hostname, port, &hints, &srvinfo);
  if (errcode != 0)
    {
      perror ("getaddrinfo");
      return -1;
    }

//   printf ("Host: %s\n", hostname);
  for(p = srvinfo; p != NULL; p = p->ai_next){
      switch(p->ai_family){
          case AF_INET:
            ptr = &((struct sockaddr_in *) p->ai_addr)->sin_addr;
            break;
        
          case AF_INET6:
            ptr = &((struct sockaddr_in6 *) p->ai_addr)->sin6_addr;
            break;
      }
      inet_ntop(p->ai_family, ptr, addrstr, sizeof(addrstr));
        if(p->ai_canonname != '\0'){
                printf ("\nIPv%d address: %s (%s)\n", p->ai_family == PF_INET6 ? 6 : 4,
                addrstr, p->ai_canonname);
        }

      if((sd = socket(srvinfo->ai_family, srvinfo->ai_socktype, srvinfo->ai_protocol)) < 0){
          perror("socket failed");
          continue;
      } else {
          break;
  }

    freeaddrinfo(srvinfo);

    if(p == NULL){  
        fprintf(stderr, "Erro");
        exit(0);
    } else {
        return(sd);
    }
}

SSL_CTX *InitCTX(void)
{
    SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();     // Load cryptos, et.al. ∗/
    SSL_load_error_strings();         // Bring in and register error messages ∗/
    method = TLSv1_2_client_method(); // Create new client−method instance ∗/
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