#include <iostream>
using namespace std;

#include <stdio.h>
#include <winsock2.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <assert.h>
#include <ws2tcpip.h>
#include <ws2spi.h>
#include <Iphlpapi.h>
#include <vector>
#include <sstream>
#include <map>
#include <winsock2.h>
#include <fstream>
#include <windows.h>
#include <mutex>
#include <thread>

//#include <netdb.h>
//#include <sys/socket.h>


#define PORT 53
#define MAXSIZE 1024

typedef struct DnsHeader{
    unsigned short TranID;
    unsigned short Flags;
    unsigned short QueryCount;
    unsigned short AnswerCount;
    unsigned short AuthoriryCount;
    unsigned short AdditionalCount;
}DnsHeader;

typedef struct Pocket{
    bool available; // true or false
    char buff[256]; // recv_buff
    int pocket_size; // buff_size
    struct sockaddr_in recv_from; // recv_from
}Pocket, *pPocket;

int Init_WSA();
int Create_SOCKET(SOCKET *S_Socket);
int Bind_addr(SOCKET S_Socket);

void send_out(char * buff, int buff_size, struct sockaddr_in recv_from, SOCKET my_socket, int thread_id);
void encodelocaldns(char *buff, int pocket_size, struct sockaddr_in recv_from, string ip_addr, DnsHeader Dnshdr, SOCKET my_socket, int thread_id);
DnsHeader HandleDnsHeader(char * buff);
void handle_pocket(char *buff, int pocket_size, struct sockaddr_in recv_from, map<string, string> dnsmap, SOCKET my_socket, int thread_id);
map<string, string> load_file();
void DNSHandleThread(map<string, string>dnsmap, SOCKET my_socket, int thread_id);
Pocket GetDNSPocket();


