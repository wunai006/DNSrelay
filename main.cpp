#include "declare.h"


/* std::mutex
 *             mutex.lock();   获取mutex,若失败,则等待
 *             mutex.try_lock(); 尝试获取mutex,若失败,不等待,return 0;
 *             mutex.unlock(); 释放当前mutex
 */

#define THREADDEBUG std::cout << "[Thread " << thread_id << "]: "

    std::mutex pool_mutex;
    Pocket *DNSPocket = new Pocket[MAXSIZE];

// main
int main()
{
    // 初始化WSA
    if(Init_WSA()) exit(1);

    // 创建描述符
    SOCKET my_socket;
    if(Create_SOCKET(&my_socket)) exit(1);

    // 绑定端口地址
    if(Bind_addr(my_socket)) exit(1);

    for(int i = 0; i < MAXSIZE; i++) DNSPocket[i].available = true;

    printf("****   Server is running    ****\n");

    map<string, string> dnsmap = load_file();

	std::thread dns_thread_1(DNSHandleThread, dnsmap, my_socket, 1);
	Sleep(20);
	std::thread dns_thread_2(DNSHandleThread, dnsmap, my_socket, 2);
    Sleep(20);
    cout<<"[MainThread] begins:"<<endl;
    while(1)
    {
        char buff[512];
        memset(buff, 0, sizeof(buff));
        int len = sizeof(struct sockaddr_in);
        struct sockaddr_in recv_from;
        int pocket_size = (int)recvfrom(my_socket, buff, sizeof(buff) - 1, 0, (struct sockaddr*)&recv_from, &len);
        if(pocket_size <= 0)
            continue;
        printf("[MainThread] : receive pocket_size byte : %d\n", pocket_size);
        for(int i = 0; i < MAXSIZE; i++)
        {
            if(DNSPocket[i].available == true)
            {
                DNSPocket[i].available = false;
                for(int j = 0; j < pocket_size; j++)
                    DNSPocket->buff[j] = buff[j];
                DNSPocket->pocket_size = pocket_size;
                DNSPocket->recv_from = recv_from;
            }
        }
    }
    // 结束WSA
    WSACleanup();
    return 0;
}

// 初始化WSA
int Init_WSA()
{
    WORD versionRequired = MAKEWORD(2, 2);
    WSADATA wsadata;
    if(WSAStartup(versionRequired, &wsadata) != 0)
    {
        printf("初始化WinSock失败\n");
        return 1;
    }
    return 0;
}

// 创建描述符
int Create_SOCKET(SOCKET *S_Socket)
{
    SOCKET Socket = socket(AF_INET, SOCK_DGRAM, 0);
    if(Socket == INVALID_SOCKET)
    {
        printf("Socket creation failed");
        WSACleanup();
        return 1;
    }
    else
    {
        *S_Socket = Socket;
        return 0;
    }
}

// 绑定"127.0.0.1"IP 和 53 端口
int Bind_addr(SOCKET S_Socket)
{
    struct sockaddr_in addr;   // 绑定一个端口
    memset(&addr, 0, sizeof(struct sockaddr_in));
    addr.sin_family = AF_INET; // 协议族 固定值
    addr.sin_port = htons(53); // 53端口 UDP传输
    addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
    if(bind(S_Socket, (struct sockaddr *)&addr, sizeof(addr)) == SOCKET_ERROR)
    {
        printf("Bind socket error!\n");
        return 1;
    }
    return 0;
}

// 本地未发现,向上发送dns请求
void send_out(char * buff, int buff_size, struct sockaddr_in recv_from, SOCKET my_socket, int thread_id)
{
    unsigned short ID = (((int)buff[0])<<8) + (int)buff[1];
    uint8_t buff0 = buff[0];
    uint8_t buff1 = buff[1];
    SOCKET out_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if(out_socket == INVALID_SOCKET)
    {
        printf("out_socket created error!\n");
        return;
    }
//    buff[0] = 0x00;
//    buff[1] = thread_id;
    struct sockaddr_in out_addr;
    out_addr.sin_family = AF_INET;
    out_addr.sin_addr.S_un.S_addr = inet_addr("10.3.9.4");  // 10.3.9.4
    out_addr.sin_port = htons(53);

    if(sendto(out_socket, buff, buff_size, 0, (struct sockaddr *)&out_addr,sizeof(struct sockaddr)) == SOCKET_ERROR)
    {
        THREADDEBUG <<"out_socket send error!\n";
        return;
    }

    char buff_recv[512];
    memset(buff_recv,0 ,sizeof(buff_recv));

    int len = sizeof(struct sockaddr_in);
    int ret_size = recvfrom(out_socket, buff_recv, 511, 0, (struct sockaddr *)&out_addr, &len);
    if(ret_size <= 0)
    {
        THREADDEBUG <<"Receive nothing!\n";
        return;
    }
    buff_recv[0] = buff0;
    buff_recv[1] = buff1;
    if(sendto(my_socket, buff_recv, ret_size, 0, (struct sockaddr *)&recv_from, sizeof(struct sockaddr)) == SOCKET_ERROR)
    {
        THREADDEBUG <<"to_back_to socket send error!\n";
        return;
    }
    THREADDEBUG <<"Upper socket processed over!\n";
}

// 处理本地文件ip
void encodelocaldns(char *buff, int pocket_size, struct sockaddr_in recv_from, string ip_addr, DnsHeader Dnshdr, SOCKET my_socket, int thread_id, int flag)
{
    char request_data[512];
    memset(request_data, 0, sizeof(request_data));
    for(int i = 0; i < pocket_size; i++)
    {
        request_data[i] = buff[i];
    }
    // Header
//    request_data[0] = Dnshdr.TranID>>8;
//    request_data[1] = Dnshdr.TranID; // TranID
    request_data[2] = 0x81;
    request_data[3] = 0x80;// Flags
    request_data[4] = 0x00;
    request_data[5] = 0x01;// QueryCount
    request_data[6] = 0x00;
    request_data[7] = 0x01;// AnswerCount
    request_data[8] = 0x00;
    request_data[9] = 0x00;// AuthorityCount
    request_data[10] = 0x00;
    request_data[11] = 0x00;// AdditionalCount
    // Query
    // Same as the origin one
    // Answer
    request_data[pocket_size] = 0xC0;
    request_data[pocket_size + 1] = 0x0C;// Name
    request_data[pocket_size + 2] = 0x00;
    request_data[pocket_size + 3] = 0x01;// Type
    request_data[pocket_size + 4] = 0x00;
    request_data[pocket_size + 5] = 0x01;// Class
    request_data[pocket_size + 6] = 0x00;
    request_data[pocket_size + 7] = 0x00;
    request_data[pocket_size + 8] = 0x01;
    request_data[pocket_size + 9] = 0x00;// TTL = 64s
    request_data[pocket_size + 10] = 0x00;
    request_data[pocket_size + 11] = 0x04;// DataLength

    pocket_size += 12;// To RData
    // RData
    int Count = 0;
    for(unsigned int i = 0; i < ip_addr.length(); i++)
    {
        if(ip_addr[i] == '.')
        {
            request_data[pocket_size] = Count;
            Count = 0;
            pocket_size++;
            continue;
        }
        Count = Count * 10 + ip_addr[i] - '0';
    }
    request_data[pocket_size] = Count;
    pocket_size++;
    if(flag)
    {
        request_data[3] = 0x83;
        THREADDEBUG << "_____________WRONG DOMAIN NAME REQUEST_____________\n";
    }

    if(sendto(my_socket, request_data, pocket_size, 0, (struct sockaddr *)&recv_from, sizeof(struct sockaddr)) == SOCKET_ERROR)
    {
        printf("Send error!");
        return;
    }
    THREADDEBUG <<"Local After Send Data ... \n";
}

// 解析包头
DnsHeader HandleDnsHeader(char * buff)
{
    DnsHeader tmp;
    tmp.TranID = (int)buff[0] * 256 + (int)buff[1];
    tmp.Flags  = (int)buff[2] * 256 + (int)buff[3];
    tmp.QueryCount = (int)buff[4] * 256 + (int)buff[5];
    tmp.AnswerCount = (int)buff[6] * 256 + (int)buff[7];
    tmp.AuthoriryCount = (int)buff[8] * 256 + (int)buff[9];
    tmp.AdditionalCount = (int)buff[10] * 256 + (int)buff[11];
    return tmp;
}

// 线程处理pocket中的数据
void DNSHandleThread(map<string, string>dnsmap, SOCKET my_socket, int thread_id)
{
    Sleep(100);
    THREADDEBUG << "create successfully!" <<endl;
    while(1)
    {
        Pocket req;
        req.available = true;
        while( req.available == true)
        {
            Sleep(20);
            req = GetDNSPocket();
        }

        char buff[512];
        memset(buff, 0, sizeof(buff));
        for(int i = 0; i < req.pocket_size; i++)
        {
            buff[i] = req.buff[i];
        }

        struct sockaddr_in recv_from = req.recv_from;

        int pocket_size = req.pocket_size;

        if(pocket_size <= 0)
            continue;

        THREADDEBUG << "process pocket_size byte : " << pocket_size <<endl;
        handle_pocket(buff, pocket_size, recv_from, dnsmap,my_socket, thread_id);
    }
}

// Get Pocket from pocket_pool
Pocket GetDNSPocket()
{
    Pocket ret;
    ret.available = true;
    if(pool_mutex.try_lock())  // try to use mutex
    {
        for(int i = 0; i < MAXSIZE; i++)
        {
            if(DNSPocket[i].available == false)  // find a pocket to decode
            {
                ret = DNSPocket[i];
                DNSPocket[i].available = true;
                break;
            }
        }
        pool_mutex.unlock();
    }
    return ret;
}

// 处理接收到的包
void handle_pocket(char *buff, int pocket_size, struct sockaddr_in recv_from, map<string, string> dnsmap, SOCKET my_socket, int thread_id)
{
    int len = sizeof(struct sockaddr_in);
    char * tmp = buff;
    int flag = 0; // flag for the ip = "0.0.0.0"

    if((buff[2] & 0x80) == 0) // 如果是查询报文的话
    {
        DnsHeader DnsHdr = HandleDnsHeader(buff);

        if((DnsHdr.Flags & 0x0007) == 3)
        {
            printf("Flags & 0x0007 == 3...Error!\n");
            return;
        }
        map<string, string> QuireMap = dnsmap;

        // 获取域名,根据报文格式RFC
        string domain_name = "";
        for(int i = 12; i < pocket_size; )
        {
            if(tmp[i] == 0)
                break;
            int Count = (int)tmp[i] + i + 1;
            for(i++; i < Count; i++)
            {
                domain_name += tmp[i];
            }
            if(tmp[i] != 0)
                domain_name += ".";
        }
        map<string, string>::iterator iter;
        THREADDEBUG << "Decoded domain name : " << domain_name.c_str() <<endl;
        if(QuireMap.count(domain_name))  // 存在本地文件中
        {
            iter = QuireMap.find(domain_name);
            THREADDEBUG << "Local Current IP : " << iter->second.c_str() <<endl;
            if(!strcmp(iter->second.c_str(), "0.0.0.0"))
                flag = 1;
            // 编码进行传输
            encodelocaldns(buff, pocket_size, recv_from, iter->second, DnsHdr, my_socket, thread_id, flag);
        }
        else // 不存在本地文件中，送出
        {
            THREADDEBUG << "Send out to the Internet!" <<endl;
//            printf("不在本地文件中,送出\n");
            send_out(buff, pocket_size, recv_from, my_socket, thread_id);
        }
    }
    else // 响应报文不做处理
    {
        THREADDEBUG<<"这是一个响应报文,不做处理!!!!!!!!!!!!!!!!\n";
    }
}

// 加载本地文件
map<string, string> load_file()
{
    std::ifstream infile;
    map<string, string> dnsmap;
    string ip, domain;

    infile.open("dnsrelay.txt");
    if(!infile) cout<<"本地文件读取错误\n";
    while(!infile.eof())
    {
        infile>>ip;
//        cout<<ip<<" ";
        infile>>domain;
//        cout<<domain<<endl;
        dnsmap[domain] = ip;
    }
    infile.close();
    return dnsmap;
}



