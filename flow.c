#include <stdio.h>
#include <stdlib.h>
#include <string.h>


    #include <netdb.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>


#include <pcap.h>
#include <err.h>
#include <sys/sysinfo.h>

#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include <getopt.h>




/* STRUCTURE: sniff_ip, sniff_tcp, TAKEN FROM https://www.tcpdump.org/pcap.html, AUTHOR: Tim Carstens, Copyright 2002 Tim Carstens */

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518
/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
/* Ethernet addresses are 6 bytes */
//#define ETHER_ADDR_LEN	6

int flow_cache = 0;


/* IP header */
struct sniff_ip 
{
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* don't fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp 
{
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct sniff_udp
{
    u_short SrcPort;
    u_short DstProt;
    u_short Len;
    u_short Sum;
};

struct NetFlow
{
    //HEAD
    u_short Version;
    u_short Count;
    u_int SysUptime;
    u_int unix_sec;
    u_int unix_nsecs;
    u_int flow_sequence;
    u_char engine_type;
    u_char engine_id;
    u_short sampling_interval;
    //BODY
    struct in_addr srcaddr;
    struct in_addr dstaddr;
    u_int nexthop;
    u_short input;
    u_short output;
    u_int dPkts;
    u_int dOctest;
    u_int First;
    u_int Last;
    u_short srcport;
    u_short dstport;
    u_char pad1;
    u_char tcp_flags;
    u_char prot;
    u_char tos;
    u_short src_as;
    u_short dst_as;
    u_char src_mask;
    u_char dst_mask;
    u_short pad2;
};

typedef struct Node
{
    char* Proto;  
    struct in_addr SrcIP;
    struct in_addr DstIP;
    int SrcPort;
    int DstPort;
    int Tos;
    int FirstpacketTime;
    int LastpacketTime;
    int FirstN;
    int LastN;
    int Length;
    int PacketCount;
    int FlowNumber;
    u_char tcp_flags;

    struct Node *next;
 } *Node;

typedef struct 
{
	Node FirstNode;
} LinkedList;

void init_linked_list( LinkedList *list ) 
{
	list->FirstNode = NULL;
}

void dispose_linked_list( LinkedList *list ) 
{
	if (list->FirstNode != NULL)
	{
		if (list->FirstNode->next != NULL)
		{
			for(Node tmp = list->FirstNode; list->FirstNode != NULL; list->FirstNode = list->FirstNode->next)
			{
			free(tmp);
            tmp = list->FirstNode->next;
			}
		}
		Node tmp = list->FirstNode;
		free(tmp);					

		list->FirstNode = NULL;	
	}
}

void remove_node(LinkedList *list, Node node) 
{
    if (list->FirstNode == node)
    {
        if (node->next == NULL)
        {
            free(node);
            list->FirstNode = NULL;
            return;
        }
        else
        {
            list->FirstNode = list->FirstNode->next;
            free(node);
            return;
        }   
    }
    else
    {
        for(Node tmp = list->FirstNode; tmp != NULL; tmp = tmp->next)
        {
            if (tmp->next == node)
            {
                tmp->next = tmp->next->next;
                free(node);
                return;
            }
        }
    }
}

struct timeval Time;
int TotalFlowCount = 0;

void insert_linked_list(LinkedList *list, const struct sniff_ip *IP, struct pcap_pkthdr *header, u_char th_flags) 
{
	Node NewNode = malloc(sizeof(struct Node));	
     
    static int FlowCount = 0;
    FlowCount++;

    NewNode->FirstpacketTime = header->ts.tv_sec;
    NewNode->LastpacketTime = header->ts.tv_sec;

    NewNode->SrcIP = IP->ip_src;
    NewNode->DstIP = IP->ip_dst;
    NewNode->Tos = IP->ip_tos;
    NewNode->Length = ntohs(IP->ip_len);
    NewNode->PacketCount = 1;
    NewNode->FlowNumber = FlowCount;

    NewNode->FirstN = header->ts.tv_usec;
    NewNode->LastN = header->ts.tv_usec;

    NewNode->tcp_flags = th_flags;
    NewNode->SrcPort = 0;
    NewNode->DstPort = 0;

	NewNode->next = NULL;		
	if (list->FirstNode != NULL)
    {
        Node tmp;
        for(tmp = list->FirstNode; tmp->next != NULL; tmp = tmp->next);
        //NewNode->next = list->FirstNode;
        //list->FirstNode = NewNode;
        tmp->next = NewNode;
	}
    else
    {
        list->FirstNode = NewNode;
    }
}

void print_linked_list(LinkedList *list)
{
    for(Node tmp = list->FirstNode; tmp != NULL; tmp = tmp->next)
    {
        printf("---------------------------\n");
        printf("Flow number: %i\n", tmp->FlowNumber);
        printf("\n      First packet Time: %i", tmp->FirstpacketTime);
        printf("\n      First NN packet Time: %i", tmp->FirstN);
        printf("\n      Last packet Time: %i", tmp->LastpacketTime);
        printf("\n      First NN packet Time: %d", tmp->LastN);
        printf("\n      Tos: %i", tmp->Tos);
        printf("\n      SrcIP: %s", inet_ntoa(tmp->SrcIP));
        printf("\n      DstIP: %s", inet_ntoa(tmp->DstIP));
        printf("\n      Length: %i", tmp->Length);
        printf("\n  Proto: %s", tmp->Proto);
        printf("\n  TCP Flags: %i", tmp->tcp_flags);
        printf("\n  SrcPort: %i", tmp->SrcPort);
        printf("\n  DstPort: %i", tmp->DstPort);
        printf("\n  PacketCount: %i\n", tmp->PacketCount);
        printf("---------------------------\n");
    }
}

void PrintPacket(const struct sniff_ip *ip, int Time ,char *Proto,u_char SrcPort,u_char DstPort)
{
    static int packet_count = 0;
    packet_count++; 

    printf("\nPacket number %d:\n", packet_count);
    printf("        Time: %i\n", Time);
    printf("        Tos: %d\n", ip->ip_tos);
	printf("        From: %s\n", inet_ntoa(ip->ip_src));
	printf("        To: %s\n", inet_ntoa(ip->ip_dst));
    printf("   Protocol: %s\n", Proto);
    printf("   Src port: %d\n", ntohs(SrcPort));
	printf("   Dst port: %d\n", ntohs(DstPort));

    printf("\n   |PacSize: %i|", htons(ip->ip_len));
    printf("\n   |CACHE: %i|\n", flow_cache);
}

/*CODE FOR SENDING DATA ON SERVER TAKEN FROM https://moodle.vut.cz/pluginfile.php/502893/mod_folder/content/0/tcp/echo-server2.c?forcedownload=1, 
AUTHOR: Petr Matousek, Copyright 2016 Petr Matousek*/
void send_flow(Node flow, char* adress,char* port,struct pcap_pkthdr *header)
{
    static int flowcount = 0;

    struct NetFlow tmp;
    tmp.Version = htons(5);
    tmp.Count = htons(1);
    tmp.SysUptime = htonl((header->ts.tv_sec - Time.tv_sec)* 1000 + (header->ts.tv_usec - Time.tv_usec)/1000);
    tmp.unix_sec = htonl(header->ts.tv_sec); 
    tmp.unix_nsecs = htonl(header->ts.tv_usec * 1000);
    tmp.flow_sequence = htonl(flowcount);
    flowcount++;
    tmp.engine_type = 0;       
    tmp.engine_id = 0;         
    tmp.sampling_interval = 0;
 
    tmp.srcaddr = flow->SrcIP;
    tmp.dstaddr = flow->DstIP;
    tmp.nexthop = 0;
    tmp.input = 0;
    tmp.output = 0;
    tmp.dPkts = htonl(flow->PacketCount);
    tmp.dOctest = htonl(flow->Length);
    tmp.First = htonl(((flow->FirstpacketTime - Time.tv_sec)*1000) + (flow->FirstN - Time.tv_usec)/1000);
    tmp.Last = htonl(((flow->LastpacketTime - Time.tv_sec)*1000) + (flow->LastN - Time.tv_usec)/1000);
    tmp.srcport = htons(flow->SrcPort);
    tmp.dstport= htons(flow->DstPort);
    tmp.pad1 = 0;
    tmp.tos = flow->Tos;
        if ((strcmp(flow->Proto, "TCP")) == 0)
        {
            tmp.prot = 6;
            tmp.tcp_flags = flow->tcp_flags;
        }
        else if ((strcmp(flow->Proto, "UDP")) == 0)
        {
            tmp.prot = 17;
            tmp.tcp_flags = 0;
        }
        else    //icmp
        {
            tmp.prot = 1;
            tmp.tcp_flags = 0;
        }  
    tmp.src_as = 0;
    tmp.dst_as = 0;
    tmp.src_mask = 32;
    tmp.dst_mask = 32;
    tmp.pad2 = 0;

    int sock;                        
    int msg_size = sizeof(tmp), i;
    struct sockaddr_in server;  
    // network host entry required by gethostbyname()     
    struct hostent *servent;                
    char buffer[msg_size];

    // erase the server structure
    memset(&server,0,sizeof(server)); 
    server.sin_family = AF_INET;

    // check the first parameter
    if ((servent = gethostbyname(adress)) == NULL) 
        errx(1,"gethostbyname() failed\n");

    // copy the first parameter to the server.sin_addr structure
    memcpy(&server.sin_addr,servent->h_addr,servent->h_length); 

    // server port (network byte order)
    server.sin_port = htons(atoi(port));        

    //create a client socket
    if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   
        err(1,"socket() failed\n");

    // create a connected UDP socket
    if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1)
        err(1, "connect() failed");

    //copy structure to buffer
    memcpy(buffer, &tmp, msg_size);
    // send data to the server
    i = send(sock,buffer,msg_size,0);     

    // check if data was sent correctly
    if (i == -1)                   
      err(1,"send() failed");
    else if (i != msg_size)
      err(1,"send(): buffer written partially");

    close(sock);
}

/*CODE FOR "ip=..." AND "switch(ip->ip_p)" TAKEN FROM https://www.tcpdump.org/other/sniffex.c, AUTHOR: Tim Carstens, Copyright 2002 Tim Carstens*/
void got_packet(struct pcap_pkthdr *header, const u_char *packet, int ActiveTimer, int InactiveTimer, int Count, LinkedList *list,char* adress,char* port)
{
    //print_linked_list(list);
	struct sniff_ip *ip;              
	const struct sniff_tcp *tcp;            
    const struct sniff_udp *udp;            
	int size_ip;
    static int packetcount = 0;
    if(packetcount == 0)
    {
        Time = header->ts;
    }
    packetcount++;

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) 
		return;

    if(list->FirstNode != NULL)
    {
        /*Checking time for all flows*/
        for(Node tmp = list->FirstNode; tmp != NULL; tmp = tmp->next)
        {   
            if( ((header->ts.tv_sec - tmp->FirstpacketTime) > ActiveTimer) || ((header->ts.tv_sec - tmp->LastpacketTime) > InactiveTimer) )
            {
                send_flow(tmp, adress, port, header);
                flow_cache --;
                remove_node(list, tmp);  
                if (tmp == NULL)
                    break;
            }
        }
    } 

    char* Proto; 
    int SrcPort,DstPort; 
    u_char  th_flags; 
    /*Looking for right protocol*/
	switch(ip->ip_p) 
    {
		case IPPROTO_TCP:
            tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
            Proto = "TCP";
            SrcPort = ntohs(tcp->th_sport);
            DstPort = ntohs(tcp->th_dport);
            th_flags = tcp->th_flags;
			break;

		case IPPROTO_UDP:

            udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
            Proto = "UDP";
            SrcPort = ntohs(udp->SrcPort);
            DstPort = ntohs(udp->DstProt);
            th_flags = 0;
			break;

		case IPPROTO_ICMP:
            Proto = "ICMP";
            SrcPort = 0;
            DstPort = 0;
            th_flags = 0;
			break;

		default:
			return;
    }

    int CreateNewFlow = 1;
    if(list->FirstNode != NULL)
    {
        /*Looking for flow where packet can by added*/
        for(Node tmp = list->FirstNode; tmp != NULL; tmp = tmp->next)
        {
            if((tmp->SrcIP.s_addr == ip->ip_src.s_addr) && (tmp->DstIP.s_addr == ip->ip_dst.s_addr) 
            && (tmp->Tos == ip->ip_tos) && (strcmp(tmp->Proto,Proto)==0) && (tmp->SrcPort == SrcPort) && (tmp->DstPort == DstPort))
            {   
                tmp->LastpacketTime = header->ts.tv_sec;
                tmp->PacketCount++;
                tmp->Length += ntohs(ip->ip_len);
                tmp->tcp_flags = tmp->tcp_flags | th_flags; 
                tmp->LastN = header->ts.tv_usec;

                CreateNewFlow = 0;  
                break;
            }
        }
    }

    //creating new flow
    if (CreateNewFlow == 1)
    {
        //if cache have not enought space for new flow last flow will by deleted and sended
        if (flow_cache + 1 > Count)
        {
            Node tmp = list->FirstNode; 
            //find last flow in list
            send_flow(tmp, adress, port, header);
            flow_cache --;
            remove_node(list, tmp);
        }
        insert_linked_list(list,ip,header, th_flags);

        Node tmp; 
        //find last flow in list
        for(tmp = list->FirstNode; tmp->next != NULL; tmp = tmp->next);
        tmp->Proto = Proto;
        tmp->SrcPort = SrcPort;
        tmp->DstPort = DstPort;
        flow_cache++ ;
        TotalFlowCount ++;
    }

return;}

int main(int argc,char **argv)
{
    char* File = "-";
    char* NetflowCollectorPort = NULL;
    int ActiveTimer = 60;
    int InactiveTimer = 10;
    int Count = 1024;

    int opt;
    while((opt = getopt(argc, argv, "f:c:a:i:m:h")) != -1) 
    { 
        switch(opt) 
        { 
            case 'f': 
                File = optarg;
                break; 
            case 'c': 
                NetflowCollectorPort = optarg;
                break;
            case 'a': 
                ActiveTimer = atoi(optarg);
                if (ActiveTimer < 0)
                    errx(1,"ActiveTimer can not be smaller then 0");
                break; 
            case 'i': 
                InactiveTimer = atoi(optarg);
                if (InactiveTimer < 0)
                    errx(1,"InactiveTimer can not be smaller then 0");
                break; 
            case 'm': 
                Count = atoi(optarg);
                if (Count < 1)
                    errx(1,"Count can not be smaller then 1");
                break;
            case 'h':
                printf("\n./flow [-f <file>] [-c <netflow_collector>[:<port>]] [-a <active_timer>] [-i <inactive_timer>] [-m <count>]\n");
                printf("\n-f <file> meno analyzovaného súboru v prípade, že nie je zadaný parameter \\-f vstup sa očakáva ́zo STDIN.");
                printf("\n-c <neflow collector:port> IP adresa alebo hostname NetFlow kolektoru pokiaľ nie je zadaný parameter –c tak IP je nastavená na 127.0.0.1:2055.");
                printf("\n-a <active timer> doba v sekundách po ktorej budú aktívne záznamy exportované na kolektor v prípade, že nieje uvedený parameter –a, je active timer nastavený na 60s.");
                printf("\n-i <seconds> doba v sekundách od príchodu posledného packetu ktorá ak bude prekročená tak budú neaktívne záznamy exportované na kolektor, ak nie je zadaný parameter –i východzia hodnota je nastavenána 10s.");
                printf("\n-m <count> velikost flow-cache. Pri dosiahnutí maximálnej velikosti dôjde k exportu najstaršieho záznamu v cachy na kolektor ak nieje -m zadané východzia hdonota je 1024.\n");
                printf("\nVšetky parametry sú brané ako volitelné. Pokiaľ nneiktorý z parametrov neni uvedený, použije se miesto neho východzia hodnota.\n");
                return 0; 
            case '?':
                return -1;
        } 
    } 

    char* adress = "127.0.0.1";
    char* port = "2055";

    //if was deteced netflowcollector in args 
    if (NetflowCollectorPort != NULL)
    {
        //netflowcollcetor have adress and port 
        if(strchr(NetflowCollectorPort,':')!=NULL)
        {   
            port = strtok(NetflowCollectorPort,":");
            adress = port;
            port = strtok(NULL,":");
        }
        //netflowcollector have onlny adress
        else
        {   
            adress = strtok(NetflowCollectorPort,":");
        }
    }
    pcap_t *handle;
    const unsigned char*packet;
    struct pcap_pkthdr header;
    char error_buffer[PCAP_ERRBUF_SIZE];

    LinkedList list;
    init_linked_list(&list);
    struct pcap_pkthdr *last_header;

    if ( (handle = pcap_open_offline(File, error_buffer)) == NULL)
        err(1,"File (%s) does not exists", File);

    while ((packet = pcap_next(handle,&header)) != NULL)    
        {
           got_packet(&header, packet, ActiveTimer, InactiveTimer, Count, &list, adress, port);
           last_header = &header;
        }
    pcap_close(handle);
    
    //sending rest flows in list
    for(Node tmp = list.FirstNode; tmp != NULL; tmp = tmp->next)
    {   
        send_flow(tmp, adress, port, last_header);
        remove_node(&list, tmp);
    }
    dispose_linked_list(&list);

return 0;}