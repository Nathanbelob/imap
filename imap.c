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
#include <openssl/bio.h>
#include <openssl/evp.h>

#define FAIL -1
#define PORT "993"
#define HOST "imap.gmail.com"
#define NULO '\0'

int hname_to_ip(const char *, const char *);

SSL_CTX *InitCTX(void);
void ShowCerts(SSL *);

int main()
{
    SSL_CTX *ctx;
    int server = 0;
    SSL *ssl;
    char buf[1024];
    char bufbase64[1024] = "";
    char response[5000] = {0};
    char acClientRequest[1024] = {0};
    char acClientRequest2[1024] = {0};
    char acClientRequest3[1024] = {0};
    char acClientRequest4[1024] = {0};
    char acClientRequest5[1024];
    int bytes = 0;
    const char *hostname, *portnum;
    FILE * fp = fopen ("image.txt","w");

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
        sprintf(acClientRequest, "Aa login seminariosvi@gmail.com gerenciaRedes2019\r\n"); // construct reply ∗/

        printf("\n\nConnected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);                                           // get any certs ∗/
        SSL_write(ssl, acClientRequest, strlen(acClientRequest)); // encrypt & send message ∗/
        SSL_read(ssl, buf, sizeof(buf));                  // get reply & decrypt ∗/
        SSL_read(ssl, buf, sizeof(buf));                  // get reply & decrypt ∗/
        printf("Received: \"%s\"\r\n", buf);

        sprintf(acClientRequest2, "Bb list \"\" \"*\"\r\n"); // construct reply ∗/
        SSL_write(ssl, acClientRequest2, strlen(acClientRequest2)); // encrypt & send message ∗/
        SSL_read(ssl, buf, sizeof(buf));                  // get reply & decrypt ∗/
        printf("Received2: \"%s\"\n", buf);


        sprintf(acClientRequest3, "Cc select \"INBOX\"\r\n"); // construct reply ∗/
        SSL_write(ssl, acClientRequest3, strlen(acClientRequest3)); // encrypt & send message ∗/
        SSL_read(ssl, buf, sizeof(buf));                 // get reply & decrypt ∗/
        printf("Received3: \"%s\"\n", buf);

        sprintf(acClientRequest5, "Ee UID FETCH 42 (BODY.PEEK[3])\r\n"); // construct reply ∗/
        SSL_write(ssl, acClientRequest5, strlen(acClientRequest5)); // encrypt & send message ∗/

        char inteiro[60000] = ""; //precisa alocar o tamanho certo para a variavel, creio estatico assim nao seja o mais certo
        int i = 0;
        while(i < 30){ // colocar uma condicao de parada quando nao tiver mais nada na resposta, da forma dinamica como está pode nao dar certo para outra imagem
            bytes = SSL_read(ssl, bufbase64, sizeof(bufbase64));    //executado em um laço de repetição 
            bufbase64[bytes] = 0;
            strcat(inteiro, bufbase64);   
            i++;
        }
 
        char *output;
        printf("Received5: %s\n", inteiro);
        fprintf(fp, inteiro);
        fclose(fp); //fecha a stream 'arqEntrada'


        SSL_free(ssl); // release connection state ∗/
        abreArquivo("image.txt");

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

int abreArquivo(char arquivo[]){
    FILE *arqEntrada;
    FILE *arqSaida;
    int line = 1;
    int linha = 1;
    int i;
    char textoArquivo[100];
    if((arqEntrada = fopen(arquivo, "r")) == 0){ //testa se o arquivo pode ser aberto
    printf("Impossivel abrir arquivo...\n"); //informa o erro
    exit(1); //finaliza execução
    }
    if((arqSaida = fopen("encoded.txt", "w")) == 0){ //testa se o arquivo pode ser aberto
    printf("Impossivel abrir arquivo...\n"); //informa o erro
    exit(1); //finaliza execução
    }
    rewind(arqEntrada); //certifica de que o cursor esta no primeiro caractere do arquivo
    for(i = 0; !feof(arqEntrada);i++){ //incrementa 'i' enquando não for fim de arquivo
    memset(textoArquivo, NULO, 100); //inicializa e/ou limpa string 'textoArquivo'
    fgets(textoArquivo, 101, arqEntrada); //pega uma string de 100 caracteres
    if(linha == line){ //se a linha for a escolhida
    fputc('\n', arqSaida); //troca a linha que o usuario quer por nova linha
    linha = linha + 1; //incrementa o contador de linhas
    continue; //volta ao inicio do loop sem executar o resto
    }
    linha = linha + 1; //incrementa o contador de linas
    fputs(textoArquivo, arqSaida); //coloca a string 'textoArquivo' no arquivo encoded.txt
    }
    printf("Linhas: %d\n", (linha-1)); //imprime quantas linhas tem o arquivo lido
    fclose(arqEntrada); //fecha a stream 'arqEntrada'
    fclose(arqSaida); //fecha a stream 'arqSaida'
}
