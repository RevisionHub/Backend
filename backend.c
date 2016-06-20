#define VERBOSE_ALL
//#include <pthread.h> 
#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
//There is not enough time to impliment AES, RSA, SSL and HTTPS by ourselves
#include <openssl/sha.h>
//For getpass function
#include <openssl/ssl.h>
#include <crypt.h>
#include "common.h"
//For SHA256
#define HASH_SIZE SHA256_DIGEST_LENGTH
#define BUFFER_SIZE 4096
#define endl "\n"
#define ERR_HTML "If you can read this, please notify the owner of this page, and include the error code:<br>"
#define CERT_FOLDER "/home/harlan/website_ssl/"
const char * HEADER = 
	"HTTP/1.1 200 OK\n"
	"Connection: close\nServer: Copelands House Computing Server (2016)" endl
	"Content-Type: text/html; charset=utf-8" endl
	endl
	endl
	//"<head>"
	//"<link rel=\x22icon\x22 href=\x22" ICON "\x22>"
	//"</head>"
	;
#define HEADER_SIZE strlen(HEADER)-1
char* make_html(char * dest, char * page)
{
	sprintf(dest, "%s%s", HEADER, page);
	return dest;
}
/*
//other daemons
char * hash (unsigned char * v)
{
	unsigned char h [HASH_SIZE];
	return SHA256(v,HASH_SIZE,h);
}
typedef struct LinkedList_struct
{
	struct LinkedList_struct * next;
	void * value;
} LinkedList;
//inline void link(LinkedList * a,LinkedList * b){a->next = b;}
typedef struct User_struct
{
	char uid[8];
	char password[HASH_SIZE];
} User;
//Should be used with the User struct
LinkedList online;
typedef struct WebPage_struct
{
	char path[256];
	User user;
}WebPage;
*/
//unsigned char* decrypt(char*){};//Do decrypt stuff

//DISK STUFF

//Attach disk daemon
void disk_read(char* path, unsigned char buffer[]);
void disk_append(char * path, unsigned char buffer[]);
//END DISK STUFF
int main (int argc, char *argv[])
{
	//Clear clear pipes
	//for (int i = 0; i < DAEMON_ENUM_LENGTH;i++) deletePipe(0,(Daemon)i);
	//Define socket
	int s = socket(AF_INET,SOCK_STREAM,6/*TCP*/);//IPPROTO_TCP
	//Stop it locking the socket up if it dies
	int true = 1;
	setsockopt(s,SOL_SOCKET,(SO_REUSEPORT | SO_REUSEADDR),&(true),sizeof(int));
	//Define socket address struct
	struct sockaddr_in addr;
	//Fill socket address struct
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("0.0.0.0");
	addr.sin_port = htons(6716);
	//Bind
	if (bind(s,(struct sockaddr *)&addr,sizeof(addr))<0) crit (-2,"Could not bind");
	//Listen
	listen(s,8192); //Big backlog
	//------------------------------------------------------------------------------------------------------------------
	//Set up socket
	info("Set up socket [%x]",s);
	//Now to pipes
	//------------------------------------------------------------------------------------------------------------------
	//Define the pipe fd array
	int pipes[DAEMON_ENUM_LENGTH];
	//Fill pipes
	for (int i = 0; i < DAEMON_ENUM_LENGTH;i++) pipes[i] = createPipe((Daemon)i);
	//------------------------------------------------------------------------------------------------------------------
	//Set up pipes
	info("Set up pipes");
	//------------------------------------------------------------------------------------------------------------------
	//SSL
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	SSL_METHOD * m;
	m = SSLv23_server_method();
	SSL_CTX * ctx;
	ctx = SSL_CTX_new(m);
	SSL_CTX_set_ecdh_auto(ctx, 1);
	printf("\n\n%sprivkey.pem\n\n",CERT_FOLDER);
	if (
		SSL_CTX_use_certificate_chain_file(ctx,CERT_FOLDER "fullchain.pem") < 0 |
		SSL_CTX_use_PrivateKey_file(ctx,CERT_FOLDER "privkey.pem",SSL_FILETYPE_PEM) < 0
		//SSL_CTX_check_private_key(ctx)
	) {ERR_print_errors_fp(stderr);crit(-69,"Bad certificate");}

	//------------------------------------------------------------------------------------------------------------------
	//EVERYTHING SET UP!
	info("Ready %i",PACKET_HEADER_SIZE);
	//------------------------------------------------------------------------------------------------------------------
	//Eternal loop
	while (1)
	{
		Packet * n = calloc(MAX_PACKET_SIZE,1);
		char * reply = calloc(MAX_PACKET_SIZE + HEADER_SIZE,1);

		struct timeval socket_timeout = {.tv_sec = 3,.tv_usec = 0};

		//Define remote socekt address struct
		struct sockaddr_in remote;
		int sremote = sizeof(remote);
		//Accept socket
		int r = accept(s,(struct sockaddr *)&remote,&sremote);

		setsockopt(r, SOL_SOCKET, SO_RCVTIMEO, (char *)&socket_timeout,sizeof(socket_timeout));
		setsockopt(r, SOL_SOCKET, SO_SNDTIMEO, (char *)&socket_timeout,sizeof(socket_timeout));

		info("Accepted socket");
		//If it fails, close
		if (r < 0) {err("Could not accept socket");close(r);continue;}

		//Turn the socket into an ssl instance
		SSL * ssl = SSL_new(ctx);
		SSL_set_fd(ssl, r);

		//Do an ssl accept
		if(SSL_accept(ssl)==-1){err("Bad ssl connection");close(r);continue;}

		char * buffer = calloc(1,BUFFER_SIZE);
		int read = SSL_read(ssl, buffer, BUFFER_SIZE);
		if (read < 1) {err("Could not read from socket");close(r);continue;}
		logrec(s,read);


		//printf("%s\n",buffer);
		char * a = strstr(buffer," ")+1;
		if ((size_t)a==1) //No space char (usually a malicious client).
		{
			err("Bad request: no space char");
			make_html(reply,ERR_HTML "Bad request: no space char");
			send(r,reply,strlen(reply),0);
			continue;
		} 
		Packet * w = calloc(MAX_PACKET_SIZE,1);
		char* html_verb = calloc(16,1);
		if (buffer-a-2>16){err("Requested page was too big for buffer");close(r);continue;} else printf ("%s", buffer);
		strncpy(html_verb,buffer,a-buffer-1);
		info("%s",html_verb);
		char * requested = calloc(2048,1);
		char * b = strstr(strstr(a," ")," ");
		if((size_t)b-(size_t)a>2048) {err("Requested page was too big for buffer");close(r);continue;}
		strncpy(requested,a,b-a);

		if (!strcmp(html_verb, "POST"))
		{
			info("Post");
			w->payloadverb = Post;
			size_t c = (size_t)strstr(a,"\r\n\r\n")+4;
			if (c == 2){err("Bad POST: no double newline char");close(r);continue;}
			w->payloadsize = strlen(requested)+1;
			strcpy(w->payload,(char*)requested);
			strcpy(w->payload+w->payloadsize,(char *)c);
			w->payloadsize += strlen((char *)c)+1;
			write_packet(pipes[User],w);
			//Timeout setup
			fd_set s;
			FD_ZERO(&s); FD_SET(pipes[Backend],&s);
			struct timeval t = {.tv_sec = 0, .tv_usec = 1000000}; //1s
			switch (select(pipes[Backend]+1, &s, NULL, NULL, &t))
			{
				case -1: err("Could not read from FIFO [%x]",r); sprintf(n->payload,"Could not read from FIFO [%x]",r); break;
				case 0: err("Page daemon timeout"); strcpy(n->payload,ERR_HTML "Page daemon timeout"); break;
				default: info("Received after %i.%06is",t.tv_sec,1000000-t.tv_usec);read_packet(pipes[Backend],n); break;
			}

		}
		else if(!strcmp(html_verb, "GET"))
		{
			if (b-a>=2048) {err("Requested page was too big for buffer");close(r);continue;}
			w->payloadverb = Get;
			w->payloadsize = strlen(requested)+1;
			strcpy(w->payload,requested);
			write_packet(pipes[Page],w);
			//Timeout setup
			fd_set s;
			FD_ZERO(&s); FD_SET(pipes[Backend],&s);
			struct timeval t = {.tv_sec = 0, .tv_usec = 1000000}; //1s
			switch (select(pipes[Backend]+1, &s, NULL, NULL, &t))
			{
				case -1: err("Could not read from FIFO [%x]",r); sprintf(n->payload,"Could not read from FIFO [%x]",r); break;
				case 0: err("Page daemon timeout"); strcpy(n->payload,ERR_HTML "Page daemon timeout"); break;
				default: info("Received after %i.%06is",t.tv_sec,1000000-t.tv_usec);read_packet(pipes[Backend],n); break;
			}
		}
		else err("Bad request");
		switch (n->payloadverb)
		{
			//When it hasn't been changed, because the select operation failed
			case 0:
			case GotPage: 
				make_html(reply,n->payload);
				SSL_write(ssl,reply,strlen(reply));
				break;
			case GotFile: SSL_write(ssl,n->payload,n->payloadsize);break;
			default: err("Bad payloadverb %i",n->payloadverb);break;
		}

		close(r);
	}
	return 0;
}          