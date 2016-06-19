#include <stdio.h>
#include <stdlib.h>
#include <sys/sockets.h>
//#include <pthread.h>
#include <sys/shm.h>
#include <sys/ipc.h>
//There is not enough time to impliment AES, RSA, SSL and HTTPS by ourselves
#include <openssl/sha.h>
#include <string.h>
//For getpass function
#include <crypt.h>
//For SHA256
#define HASH_SIZE SHA256_DIGEST_LENGTH

//other daemons
key_t DISK_MMAP;

//void attach(

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
inline void link(LinkedList * a,LinkedList * b){a->next = b;}
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
//unsigned char* decrypt(char*){};//Do decrypt stuff

//DISK STUFF

//Attach disk daemon
void disk_read(char* path, unsigned char buffer[]);
void disk_append(char * path, unsigned char buffer[]);
//END DISK STUFF

int main (int argc, char *argv[])
{
	DISK_MMAP = ftok("~/copelands_2016_disk",69); 
	shmget(DISK_MMAP,,)
	return 0;
}

