#include <stdio.h>      //fopen
#include <pcap/pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>  //inet_ntop()
#include <stdbool.h>    //bool
#include <string.h>     //memcpy
#include <stdlib.h>     //malloc


void debug_print();
void packet_filtering(char *packet);
void print_mac(uint8_t * macaddr);
bool port_check(char* packet);

void debug_print(char * packet)
{
    struct iphdr * ip_hdr = (struct iphdr *)(packet + 14);
    struct tcphdr * tcp_hdr = (struct tcphdr *)(packet + 14 + ip_hdr->ihl*4);
    //    //Ethernet
    //    printf("--------| Ether |--------\n");
    //    printf("Source mac address: ");
    //    print_mac(eth_hdr->h_source);
    //    printf("\n");
    //    printf("Destination mac address: ");
    //    print_mac(eth_hdr->h_dest);
    //    printf("\n");
    //    //IP
    //    printf("--------| IP |--------\n");
    //    printf("IP protocol: %d \n",ip_hdr->protocol);
    ////    inet_ntop(AF_INET,&ip_hdr->saddr,buf,sizeof(buf));
    //    struct sockaddr_in saddr,daddr;
    //    char *sstr,*dstr;
    //    saddr.sin_addr.s_addr=ip_hdr->saddr;
    //    daddr.sin_addr.s_addr=ip_hdr->daddr;
    //    sstr = inet_ntoa(saddr.sin_addr);
    //    printf("Source IP: %s \n",sstr);
    //    dstr = inet_ntoa(daddr.sin_addr);
    //    printf("Destination IP: %s \n",dstr);
    //    //TCP
    //    printf("--------| TCP |--------\n");
        printf("Source Port: %d \n",ntohs(tcp_hdr->source));
        printf("Destination Port: %d \n",ntohs(tcp_hdr->dest));
////    len check
//        printf("ip heaer len: %d \n",ip_hdr->ihl*4);
//        printf("tcp header len: %d \n",tcp_hdr->th_off*4);
//        printf(" + : %d\n",14+ip_hdr->ihl*4+tcp_hdr->doff*4);



}
bool port_check(char* packet)
{
    struct iphdr * ip_hdr = (struct iphdr *)(packet + 14);
    struct tcphdr * tcp_hdr = (struct tcphdr *)(packet + 14 + ip_hdr->ihl*4);
    int ip_tcp_len = ip_hdr->ihl*4 + tcp_hdr->doff *4;
    int smtp_len = ntohs(ip_hdr->tot_len) - ip_tcp_len;     //smtp data len

    uint16_t sport = ntohs(tcp_hdr->source);
    uint16_t dport = ntohs(tcp_hdr->dest);
    bool sport_smtp = false;
    bool dport_smtp = false;
    if(sport == 25 || sport == 465 || sport == 587) {sport_smtp = true;}
    if(dport == 25 || dport == 465 || dport == 587) {dport_smtp = true;}
    if((smtp_len > 0) && (sport_smtp || dport_smtp))
        return true;
    else
        return false;
}
void print_mac(uint8_t * macaddr)
{
    for(int i=0;i<6;i++){
        printf("%02x ", macaddr[i]);
    }
}

void packet_filtering(char *packet)
{
    struct iphdr * ip_hdr = (struct iphdr *)(packet + 14);
    struct tcphdr * tcp_hdr = (struct tcphdr *)(packet + 14 + ip_hdr->ihl*4);

    if(port_check(packet)){     //port check = smtp check
        uint8_t * smtp_data =(uint8_t*)(packet + 14 + ip_hdr->ihl*4 + tcp_hdr->doff*4);
        int smtp_data_len = ntohs(ip_hdr->tot_len) - ip_hdr->ihl*4 - tcp_hdr->doff*4;
        char * email = (char*)malloc(smtp_data_len-4);

        if(!memcmp(smtp_data,"EHLO",4)){
            char * buf = (char*)malloc(smtp_data_len);
            FILE *fp = fopen("./smtp-email.txt","a");
            memcpy(email,smtp_data+4,smtp_data_len-4);
            printf("email: %s \n",email);
            sprintf(buf,"%s",email);
            int i = fwrite(buf,strlen(buf),1,fp);
            if(i!=1) printf("fwrite error: \n");
            fclose(fp);
            free(buf);
        }
        free(email);
    }
}

int main(int argc,char * argv[])
{
    if(argc < 2){
        printf("ex) smtp_parser [PCAP FILE]\n");
        return -1;
    }
    if(argc > 2){
        printf("too many argument\n");
        printf("ex) smtp_parser [PCAP FILE]\n");
        return -1;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
//    pcap_t * handle=pcap_open_offline("/home/kali/Desktop/stealien/stl_smtp_parser/p1_smtp.pcap",errbuf);
    pcap_t * handle=pcap_open_offline(argv[1],errbuf);
    if(handle == NULL){
        printf("%s\n",errbuf);
        return -1;
    }
    struct pcap_pkthdr* header;
    const u_char * packet;
    while(1){
        int res = pcap_next_ex(handle,&header,&packet);
        if(res == 0) continue;
        if(res ==-1 || res ==-2) break;
        //        printf("[#]\n");
        packet_filtering((char*)packet);
    }
    return 0;
}
