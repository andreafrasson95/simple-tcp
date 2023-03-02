#define _GNU_SOURCE
#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/types.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>

#define BUF_SIZE 16000

#define CLOSED 1
#define LISTEN 2
#define SYN_RCVD 3
#define SYN_SENT 11
#define FIN_WAIT_1 4
#define FIN_WAIT_2 5
#define CLOSING 6
#define TIME_WAIT 7
#define ESTABLISHED 8
#define LAST_ACK 9
#define CLOSE_WAIT 10

#define SOCK_CONNECTING 1
#define SOCK_SENDING 2 
#define SOCK_CLOSING 3
#define SOCK_LISTENING 4
#define SOCK_CLOSED 5
#define SOCK_CONNECTED 6
#define SOCK_RECEIVING 7

/****************************************|
|                                        |
|               INDICE                   | 
*****************************************

-Handler SigAlarm      Line 223

-Handler Sig35(Sigio)  Line 270
 ---Case SYN-SENT      Line 303
 ---Case SYN-RCVD      Line 326
 ---Case ESTABLISHED   Line 340
    ---In arrivo ACK   Line 343
    ---In arrivo Dati  Line 404
    ---In arrivo FIN   Line 389
 ---Case FIN-WAIT 1    Line 452
    ---In Arrivo ACK   Line 455
    ---In Arrivo Dati  Line 524
    ---In Arrivo FIN   Line 554
 ---Case FIN-WAIT 2    Line 583
    ---In Arrivo Dati  Line 585
    ---In Arrivo FIN   Line 622
 ---Case CLOSING       Line 651
 ---Case LISTEN        Line 732

-Main                  Line 809
 ---Client             Line 905
 ---Server             Line 943

-User Commands       
 ---Myconnect          Line 985
 ---Mywrite            Line 1058
 ---Myread             Line 1111
 ---Myclose            Line 1123
 ---Mybind             Line 1161
 ---Mylisten           Line 1170
 ---Myaccept           Line 1179   
****************************************/

   
//Pseudoheader TCP
struct tcp_psheader {
  unsigned int src;
  unsigned int dst;
  unsigned short protocol;
  unsigned short tcp_len;
};
//Identificatore Connessione TCP
struct connection {
  unsigned int myip;
  unsigned int foreign_ip;
  unsigned short local_port;
  unsigned short foreign_port;
};
//Pacchetto sparso
struct fragment{
  int offset;
  unsigned int seq_number;
  int lunghezza;
  struct fragment *next;
};
//Retransmission Element
struct retr_packet{
  unsigned int seq_number;
  int lunghezza;
  struct timeval timeout;
};
//TCB
struct tcb {
  struct connection connection;
  struct tcp_psheader pshe;
  struct mysocket * sock;

  unsigned char conn_state;

  unsigned int snd_una;
  unsigned int snd_nxt;
  unsigned short snd_wnd;
  unsigned int ISS;
  unsigned int data_sent;
  char * snd_buffer;

  unsigned int rcv_next;
  unsigned int rcv_wnd;
  unsigned int IRS;
  unsigned int last_acked;
  char *rcv_buffer;
  char *last;
  
  char fin_sent;
  //Coda Pacchetti Sparsi
  struct fragment * head;
  //Coda Ritrasmissione
  struct retr_packet queue[10];
  int length_queue;
};
//Socket Listening
struct list_socket{

  char socket_state;//LISTENING O CLOSED
  unsigned short local_port;

  struct mysocket * list[5];
  char number;
};
//Socket
struct mysocket{
  char snd_buffer[10000];
  int  snd_offset;

  char rcv_buffer[BUF_SIZE];
  int last;
  int reader;

  unsigned int local_address;
  unsigned int foreign_address;
  unsigned short local_port;
  unsigned short foreign_port;

  char socket_state;
  char connection;
};
//Frame Ethernet
struct eth_frame {
  unsigned char dst[6];
  unsigned char src[6];
  unsigned short type;
  char payload[1500];
};
//Ip Datagram
struct ip_datagram {
  unsigned char ver_ihl;
  unsigned char tos;
  unsigned short totlen;
  unsigned short id;
  unsigned short flags_off;
  unsigned char ttl;
  unsigned char protocol;
  unsigned short checksum;
  unsigned int src;
  unsigned int dst;
  unsigned char payload[1500];
};
//Tcp Segment
struct tcp_segment {
  unsigned short s_port;
  unsigned short d_port;
  unsigned int seq;
  unsigned int ack;
  unsigned char data_offs;
  unsigned char flags;
  unsigned short window;
  unsigned short checksum;
  unsigned short urgent_pointer;
  unsigned char payload[1500];
};

//Metodi
int myconnect(struct mysocket* sock,unsigned short local_port,unsigned short foreign_port,unsigned int myip,unsigned int foreign_ip);
int mywrite(struct mysocket *a,char * buffer, int count);
int myread(struct mysocket *sock,char *buffer, int count);
int myclose(struct mysocket *sock);
int mybind(struct list_socket *sock,unsigned short local_port);
int mylisten(struct list_socket * a);
struct mysocket * myaccept(struct list_socket *a);
//Metodi "Basso Livello"
unsigned short checksum(unsigned char * buffer,int len);
unsigned short checksum_tcp(unsigned char *buffer, unsigned char*pshe,int len);
void crea_eth(struct eth_frame *e, unsigned char *src, unsigned char *dest,unsigned short type);
void crea_ip(struct ip_datagram *ip,int payloadlen,unsigned char proto,unsigned int dst);
void crea_tcp(struct tcp_segment* tcp, struct tcb * block,unsigned char flags,int data,char *buffer);
void retr_tcp(struct tcp_segment* tcp,struct tcb *block,unsigned int seq,unsigned char flags,int data, char *buffer);
void stampabytes(unsigned char * buffer,int quanti);

int push(struct tcb * block,int seq_number,int offset,int lunghezza);
int free_queue(struct tcb *block);
//Array TCB e Socket_Listen
struct tcb block[10];
struct list_socket  * listening[10];

//Inizializzo numero Connessioni
int CONN_NUMBER=0;
int LISTENING_SOCKETS=0;

struct timeval timeout;

//Indirizzi Vari
unsigned char mymac[6]={0x00,0x50,0x56,0x9f,0xda,0xfb};

//unsigned char myip[4]={88,80,187,84};
unsigned char myip[4]={195,231,83,161};

//Modem Casa
unsigned char gateway[6]={0x00,0x00,0x5e,0x00,0x01,0x68};

//Server prof
//unsigned char gateway[6]={0xd8,0xce,0x3a,0x2b,0xf4,0xe9};
//unsigned char gateway_server[6]={0x84,0x78,0xac,0x5a,0x1a,0x41};
unsigned char googleip[4]={142,251,163,94};

//Sockaddr
struct sockaddr_ll sll={.sll_ifindex=2};
int len=sizeof(struct sockaddr_ll);

/********************************************************
|                                                       | 
|                  HANDLER SIGALRM                      | 
|                                                       |
********************************************************/
void handler(int sig,siginfo_t *info,void *ucontext){
  int t;
  struct timeval time;

  unsigned char buffer[1500];
  struct eth_frame * eth;
  struct ip_datagram *ip;
  struct  tcp_segment *tcp;

  eth=(struct eth_frame*) buffer;
  ip=(struct ip_datagram*) eth->payload;
  tcp=(struct tcp_segment*) ip->payload;
  //CONTROLLO SU TUTTE LE CONNESSIONE SE HO SEGMENT SCADUTI
  for(int i=0;i<CONN_NUMBER;i++){
    for(int j=0;j<(block[i].length_queue);j++){
       gettimeofday(&time,NULL);
       
       if((time.tv_sec<block[i].queue[j].timeout.tv_sec))continue;
       if((time.tv_usec<block[i].queue[j].timeout.tv_usec)) continue;   
          
       struct retr_packet * tmp;
       tmp=&block[i].queue[j];
       char flags=0x10;
       if(block[i].conn_state==SYN_SENT) flags=0x2;
       if(block[i].conn_state==SYN_RCVD) flags=0x12;   

       crea_eth(eth,mymac,gateway,0x0800);
       crea_ip(ip,20+tmp->lunghezza,6,htonl(block[i].connection.foreign_ip));
       block[i].pshe.tcp_len=htons(20+tmp->lunghezza);
       retr_tcp(tcp,&block[i],tmp->seq_number,flags,tmp->lunghezza,block[i].snd_buffer);

       t=sendto(3,buffer,14+40+tmp->lunghezza,0,(struct sockaddr*)&sll,sizeof(sll));
       if(t==-1){
            perror("Send Fallita");
            exit(1);
       }
       //Aggiorno il timestamp
       timeradd(&time,&timeout,&tmp->timeout);

    }

  }
}


/******************************************************
|                                                     |
|                HANDLER SIGIO                        | 
|                                                     |  
******************************************************/
void handler_sigio(int sig,siginfo_t *info,void *ucontext){
  int t,d,i;

  unsigned char buffer[1500];
  struct eth_frame * eth;
  struct ip_datagram *ip;
  struct  tcp_segment *tcp;

  eth=(struct eth_frame*) buffer;
  ip=(struct ip_datagram*) eth->payload;
  tcp=(struct tcp_segment*) ip->payload;  
  
  t=recvfrom(3,buffer,1500,0,(struct sockaddr*) &sll,&len);
  if (t==-1){
  perror("Recv Fallita");
  exit(1);
  }
  
  for(i=0;i<CONN_NUMBER;i++){
                	   
           if((block[i].connection.myip==htonl(ip->dst))&& (block[i].connection.foreign_ip==htonl(ip->src))&&
	     (block[i].connection.local_port==htons(tcp->d_port))&& (block[i].connection.foreign_port==htons(tcp->s_port)))	  
          
                   break; 
  }

  d=block[i].conn_state;
  switch(d){     
    case(SYN_SENT):{  
     if(tcp->flags==0x12 && htonl(tcp->ack)==block[i].snd_nxt){
	block[i].rcv_next=htonl(tcp->seq)+1;  
        block[i].IRS=htonl(tcp->seq);

        block[i].length_queue--;
        block[i].snd_una++;
         
        crea_eth(eth,mymac,gateway,0x0800);
        crea_ip(ip,20,6,htonl(block[i].connection.foreign_ip));
        block[i].pshe.tcp_len=htons(20);
        crea_tcp(tcp,&block[i],0x10,0,NULL);
        
        t=sendto(3,buffer,54,0,(struct sockaddr*) &sll,sizeof(sll));
        if(t==-1){
            perror("Send Fallita");
            exit(1); 
        }
         
        block[i].conn_state=ESTABLISHED;
        block[i].sock->socket_state=SOCK_CONNECTED; 
     }
    }break;

    case(SYN_RCVD):{      
     if(tcp->flags==0x10 && htonl(tcp->seq)==block[i].rcv_next){
     
     block[i].length_queue--;    
 
     block[i].conn_state=ESTABLISHED;
     block[i].snd_nxt=block[i].ISS+1;
     block[i].snd_una=block[i].snd_nxt; 
     
     block[i].sock->socket_state=SOCK_CONNECTED;
     printf("ESTABLISHED ON PORTS %d %d ON IP %d.%d.%d.%d \n",htons(tcp->d_port),htons(tcp->s_port),((unsigned char*)&ip->src)[0],((unsigned char*)&ip->src)[1],((unsigned char*)&ip->src)[2],((unsigned char*)&ip->src)[3]);
     
     }
 
    }break; 
  
    case(ESTABLISHED):{
     
     //************************************************************ARRIVATO ACKED**************************************
     if(tcp->flags==0x10 && htonl(tcp->ack)>block[i].snd_una){
       block[i].snd_una=htonl(tcp->ack);   
       int salti,j;
       salti=0;
       for(j=0;j<(block[i].length_queue);j++){
          if((block[i].queue[j].seq_number+block[i].queue[j].lunghezza)<=block[i].snd_una) salti++; 
       }
       for(j=0;j<(block[i].length_queue-salti) && salti;j++)
          block[i].queue[j]=block[i].queue[j+salti];
       block[i].length_queue=block[i].length_queue-salti;
      //Se finestra si svuota invio dati
       while((block[i].snd_nxt-block[i].snd_una)<30 && (block[i].data_sent<block[i].sock->snd_offset)){ //FINESTRA PROVVISORIA PER PROVARE
          int a_window=30-(block[i].snd_nxt-block[i].snd_una); 
          int dati=block[i].sock->snd_offset-block[i].data_sent;
          int lunghezza;
          if(dati>=6 && a_window>=6) lunghezza=6;
          else{
           if(dati>a_window) lunghezza=a_window;
           else
           lunghezza=dati;
          }
          crea_eth(eth,mymac,gateway,0x0800);
          crea_ip(ip,20+lunghezza,6,htonl(block[i].connection.foreign_ip));
          block[i].pshe.tcp_len=htons(20+lunghezza);   
          crea_tcp(tcp,&block[i],0x10,lunghezza,block[i].snd_buffer);
          t=sendto(3,buffer,14+40+lunghezza,0,(struct sockaddr*)&sll,sizeof(sll));
          if(t==-1){
             perror("Send Fallita");
             exit(1);
          }
          //Inserisco Segment in coda di Ritrasmissione
          block[i].queue[block[i].length_queue].seq_number=block[i].snd_nxt;
          block[i].queue[block[i].length_queue].lunghezza=lunghezza;
          struct timeval time;
          gettimeofday(&time,NULL);
          timeradd(&time,&timeout,&(block[i].queue[block[i].length_queue].timeout));
          block[i].length_queue++; 
         
          block[i].snd_nxt=block[i].snd_nxt+lunghezza;
          block[i].data_sent=block[i].data_sent+lunghezza;
     
         
       }
     break;
     }
     //*************************************************IN ARRIVO FIN*****************************************
     if((tcp->flags)& 0x1){
       //Controllo se prima ho ricevuto tutto
       if(htonl(tcp->seq)==block[i].rcv_next) block[i].rcv_next++;
       write(1,"ENTRO CLOSE WAIT\n",17);
       
       crea_eth(eth,mymac,gateway,0x0800);
       crea_ip(ip,20,6,htonl(block[i].connection.foreign_ip));
       block[i].pshe.tcp_len=htons(20);
       crea_tcp(tcp,&block[i],0x10,0,NULL);
       t=sendto(3,buffer,54,0,(struct sockaddr*) &sll,sizeof(sll));
       if(t==-1){
             perror("SEND FALLITA");
             exit(1);
       }
       block[i].conn_state=CLOSE_WAIT;
       break;
     }
	
     //Arrivato Pacchetto di Dati   
     if((tcp->flags)&0x10 && htonl(tcp->seq)>=block[i].rcv_next && htons(ip->totlen)>40){
       
       int offset=(htonl(tcp->seq)-block[i].IRS-1) % BUF_SIZE;
       int avanzo;
       if((avanzo=htons(ip->totlen)-40+offset)>BUF_SIZE){
          memcpy(block[i].rcv_buffer+offset,tcp->payload,htons(ip->totlen)-avanzo);
          memcpy(block[i].rcv_buffer,(tcp->payload)+htons(ip->totlen)-avanzo,avanzo);
       }
       else
       memcpy(block[i].rcv_buffer+offset,tcp->payload,htons(ip->totlen)-40);
       
       push(&block[i],offset,htonl(tcp->seq),htons(ip->totlen)-40); 
       free_queue(&block[i]);  
       block[i].rcv_wnd=(BUF_SIZE-block[i].sock->last+block[i].sock->reader) % BUF_SIZE;
     
       write(1,"USCITO\n",7);
       crea_eth(eth,mymac,gateway,0x0800);
       crea_ip(ip,20,6,htonl(block[i].connection.foreign_ip));
       block[i].pshe.tcp_len=htons(20);
       crea_tcp(tcp,&block[i],0x10,0,NULL);
     
       t=sendto(3,buffer,54,0,(struct sockaddr*)&sll,sizeof(sll));
       if(t==-1){
          perror("Send Fallita");
	  exit(1);
	  }
     }
  
    }break;
    
    case(FIN_WAIT_1):{
     char modified=0;
     //**************************************************IN ARRIVO ACKED********************************************************************
     if((tcp->flags)&0x10 && htonl(tcp->ack)>block[i].snd_una){
       block[i].snd_una=htonl(tcp->ack);
       //Tolgo Acked da Coda Ritrasmissione
       int salti,j;
       salti=0;
       for(j=0;j<(block[i].length_queue);j++){
          if((block[i].queue[j].seq_number+block[i].queue[j].lunghezza)<=block[i].snd_una) salti++;
       }
       for(j=0;j<(block[i].length_queue-salti) && salti;j++)
          block[i].queue[j]=block[i].queue[j+salti];
       block[i].length_queue=block[i].length_queue-salti;
     
       //Se finestra si svuota invio dati
       while((block[i].snd_nxt-block[i].snd_una)<30 && (block[i].data_sent<block[i].sock->snd_offset)){ //FINESTRA PROVVISORIA PER PROVARE
          int a_window=30-(block[i].snd_nxt-block[i].snd_una);
          int dati=block[i].sock->snd_offset-block[i].data_sent;
          int lunghezza;
          if(dati>=6 && a_window>=6) lunghezza=6;
          else{
           if(dati>a_window) lunghezza=a_window;
           else
           lunghezza=dati;
          }
          crea_eth(eth,mymac,gateway,0x0800);
          crea_ip(ip,20+lunghezza,6,htonl(block[i].connection.foreign_ip));
          block[i].pshe.tcp_len=htons(20+lunghezza);
          crea_tcp(tcp,&block[i],0x10,lunghezza,block[i].snd_buffer);
          t=sendto(3,buffer,14+40+lunghezza,0,(struct sockaddr*)&sll,sizeof(sll));
          if(t==-1){
             perror("Send Fallita");
             exit(1);
          }
          //Inserisco Segment in coda di Ritrasmissione
          block[i].queue[block[i].length_queue].seq_number=block[i].snd_nxt;
          block[i].queue[block[i].length_queue].lunghezza=lunghezza;
          struct timeval time;
          gettimeofday(&time,NULL);
                 timeradd(&time,&timeout,&(block[i].queue[block[i].length_queue].timeout));
          block[i].length_queue++;

          block[i].snd_nxt=block[i].snd_nxt+lunghezza;
          block[i].data_sent=block[i].data_sent+lunghezza;

          modified=1;
       }
       if(block[i].snd_una==block[i].snd_nxt && block[i].fin_sent==1){
           block[i].conn_state=FIN_WAIT_2;
           write(1,"FIN WAIT 2\n",11);
       }

       /************************************************Se ho Segmentizzato tutto mando FIN****************************************/
       if(block[i].data_sent==block[i].sock->snd_offset && block[i].fin_sent==0){
        write(1,"MANDO FIN DA FIN WAIT 1\n",24);
        crea_eth(eth,mymac,gateway,0x0800);
        crea_ip(ip,20,6,htonl(block[i].connection.foreign_ip));
        block[i].pshe.tcp_len=htons(20);
        crea_tcp(tcp,&block[i],0x11,0,NULL);

        t=sendto(3,buffer,54,0,(struct sockaddr*)&sll,sizeof(sll));
        if(t==-1){
        perror("Send Fallita");
        exit(1);
        }
        block[i].snd_nxt++;
        block[i].fin_sent=1;
      }
     break;
     }
     //***************************************************IN ARRIVO DATI********************************************
     if((tcp->flags)&0x10 && htonl(tcp->seq)>=block[i].rcv_next && htons(ip->totlen)>40 && !modified){

       int offset=(htonl(tcp->seq)-block[i].IRS-1) % BUF_SIZE;
       int avanzo;
       if((avanzo=htons(ip->totlen)+offset-BUF_SIZE)>0){
          memcpy(block[i].rcv_buffer+offset,tcp->payload,htons(ip->totlen)-avanzo);
          memcpy(block[i].rcv_buffer,(tcp->payload)+htons(ip->totlen)-avanzo,avanzo);
       }
       else
       memcpy(block[i].rcv_buffer+offset,tcp->payload,htons(ip->totlen)-40);

       //push(offset,htonl(tcp->seq),htons(ip->totlen)-40) 

       crea_eth(eth,mymac,gateway,0x0800);
       crea_ip(ip,20,6,htonl(block[i].connection.foreign_ip));
       block[i].pshe.tcp_len=htons(20);
       crea_tcp(tcp,&block[i],0x10,0,NULL);

       t=sendto(3,buffer,54,0,(struct sockaddr*)&sll,sizeof(sll));
       if(t==-1){
          perror("Send Fallita");
          exit(1);
          }
     }
     /*****************************************IN ARRIVO FIN*********************************************************/  
     if((tcp->flags)&0x1){
       if(htonl(tcp->seq)==block[i].rcv_next) block[i].rcv_next++;
       write(1,"CLOSING DA FIN WAIT 1\n",22);
       crea_eth(eth,mymac,gateway,0x0800);
       crea_ip(ip,20,6,htonl(block[i].connection.foreign_ip));
       block[i].pshe.tcp_len=htons(20);
       crea_tcp(tcp,&block[i],0x10,0,NULL);
       t=sendto(3,buffer,54,0,(struct sockaddr*) &sll,sizeof(sll));
       if(t==-1){
             perror("SEND FALLITA");
             exit(1);
       }
       if(block[i].snd_nxt==block[i].snd_una && block[i].fin_sent==1){
        bzero((unsigned char*)&block[i],sizeof(struct tcb));
       //Elimino TCB
       for(t=i;t<CONN_NUMBER;t++)
              block[t]=block[t+1];

       CONN_NUMBER=CONN_NUMBER-1;
       printf("FINISCO,NUMERO= %d \n",CONN_NUMBER);
       break;
       }
       block[i].conn_state=CLOSING;
       break;
     }
   

    }break;

    case(FIN_WAIT_2):{
      /***********************************IN ARRIVO DATI*******************************************/
      if((tcp->flags)&0x10 && htonl(tcp->seq)>=block[i].rcv_next && htons(ip->totlen)>40){
       
       int offset=(htonl(tcp->seq)-block[i].IRS-1) % BUF_SIZE;
       int avanzo;
       if((avanzo=htons(ip->totlen)+offset-BUF_SIZE)>0){
          memcpy(block[i].rcv_buffer+offset,tcp->payload,htons(ip->totlen)-avanzo);
          memcpy(block[i].rcv_buffer,(tcp->payload)+htons(ip->totlen)-avanzo,avanzo);
       }
       else
       memcpy(block[i].rcv_buffer+offset,tcp->payload,htons(ip->totlen)-40);

       //push(offset,htonl(tcp->seq),htons(ip->totlen)-40) 

       //FIN Assieme ai Dati
       if(((tcp->flags)& 0x1) && (htonl(tcp->seq)+htons(ip->totlen)-40==block[i].rcv_next)){
           block[i].rcv_next++;
           block[i].conn_state=TIME_WAIT;
       }
       crea_eth(eth,mymac,gateway,0x0800);
       crea_ip(ip,20,6,htonl(block[i].connection.foreign_ip));
       block[i].pshe.tcp_len=htons(20);
       crea_tcp(tcp,&block[i],0x10,0,NULL);

       t=sendto(3,buffer,54,0,(struct sockaddr*)&sll,sizeof(sll));
       if(t==-1){
          perror("Send Fallita");
          exit(1);
          }
     }


     //*******************************************************IN ARRIVO FIN************************************
     if((tcp->flags) & 0x1){                                             
       if(htonl(tcp->seq)==block[i].rcv_next){ 
           block[i].rcv_next++;
           block[i].conn_state=TIME_WAIT;
       }
       write(1,"CLOSING DA FIN WAIT 2\n",22);
       crea_eth(eth,mymac,gateway,0x0800);                         
       crea_ip(ip,20,6,htonl(block[i].connection.foreign_ip));
       block[i].pshe.tcp_len=htons(20);
       crea_tcp(tcp,&block[i],0x10,0,NULL);
       t=sendto(3,buffer,54,0,(struct sockaddr*) &sll,sizeof(sll));
       if(t==-1){
             perror("SEND FALLITA");
             exit(1);
             }
       }

       if(block[i].conn_state==TIME_WAIT){
       bzero((unsigned char*)&block[i],sizeof(struct tcb));
       //Shifto Array Connessioni
       for(t=i;t<CONN_NUMBER;t++)
              block[t]=block[t+1];

       CONN_NUMBER=CONN_NUMBER-1;
       printf("NUMERO %d \n",CONN_NUMBER);
       }
     }break;
    
    case(CLOSING):{ 
        if((tcp->flags)==0x10 && htonl(tcp->ack)>block[i].snd_una){
          block[i].snd_una=htonl(tcp->ack);
          //Tolgo Acked da Coda Ritrasmissione
          int salti,j;
          salti=0;
          for(j=0;j<(block[i].length_queue);j++){
             if((block[i].queue[j].seq_number+block[i].queue[j].lunghezza)<=block[i].snd_una) salti++;
          }
          for(j=0;j<(block[i].length_queue-salti) && salti;j++)
             block[i].queue[j]=block[i].queue[j+salti];
          block[i].length_queue=block[i].length_queue-salti;

        //Ack del FIN
        if(block[i].snd_nxt==block[i].snd_una && block[i].fin_sent==1){
          write(1,"CHIUDO DA CLOSING",17);
          bzero((unsigned char*)&block[i],sizeof(struct tcb));
          //Shifto Array Connessioni
          for(t=i;t<CONN_NUMBER;t++)
               block[t]=block[t+1];

          CONN_NUMBER=CONN_NUMBER-1;
          printf("NUMERO %d \n",CONN_NUMBER);
       break;
       }
       //************************************************Se Ho Ancora da Segmentizzare, mando************************************/
       while((block[i].snd_nxt-block[i].snd_una)<30 && (block[i].data_sent<block[i].sock->snd_offset)){ //FINESTRA PROVVISORIA PER PROVARE
          int a_window=30-(block[i].snd_nxt-block[i].snd_una);
          int dati=block[i].sock->snd_offset-block[i].data_sent;
          int lunghezza;
          if(dati>=6 && a_window>=6) lunghezza=6;
          else{
           if(dati>a_window) lunghezza=a_window;
           else
           lunghezza=dati;
          }
          crea_eth(eth,mymac,gateway,0x0800);
          crea_ip(ip,20+lunghezza,6,htonl(block[i].connection.foreign_ip));
          block[i].pshe.tcp_len=htons(20+lunghezza);
          crea_tcp(tcp,&block[i],0x10,lunghezza,block[i].snd_buffer);
          t=sendto(3,buffer,14+40+lunghezza,0,(struct sockaddr*)&sll,sizeof(sll));
          if(t==-1){
             perror("Send Fallita");
             exit(1);
          }
          //Inserisco Segment in coda di Ritrasmissione
          block[i].queue[block[i].length_queue].seq_number=block[i].snd_nxt;
          block[i].queue[block[i].length_queue].lunghezza=lunghezza;
          struct timeval time;
          gettimeofday(&time,NULL);
                 timeradd(&time,&timeout,&(block[i].queue[block[i].length_queue].timeout));
          block[i].length_queue++;

          block[i].snd_nxt=block[i].snd_nxt+lunghezza;
          block[i].data_sent=block[i].data_sent+lunghezza;

         
       }
     }
       /*******************************************SE HO SEGMENTIZZATO TUTTO MANDO FIN************************************/
       if(block[i].data_sent==block[i].sock->snd_offset && block[i].fin_sent==0){
        write(1,"MANDO FIN DA CLOSING\n",21);
        crea_eth(eth,mymac,gateway,0x0800);
        crea_ip(ip,20,6,htonl(block[i].connection.foreign_ip));
        block[i].pshe.tcp_len=htons(20);
        crea_tcp(tcp,&block[i],0x11,0,NULL);

        t=sendto(3,buffer,54,0,(struct sockaddr*)&sll,sizeof(sll));
        if(t==-1){
        perror("Send Fallita");
        exit(1);
        }
        block[i].snd_nxt++;
        block[i].fin_sent=1;
      }
       
    }break;
  
    case(CLOSE_WAIT):{
     if(tcp->flags==0x10 && htonl(tcp->ack)>block[i].snd_una){
       block[i].snd_una=htonl(tcp->ack);
       int salti,j;
       salti=0;
       for(j=0;j<(block[i].length_queue);j++){
          if((block[i].queue[j].seq_number+block[i].queue[j].lunghezza)<=block[i].snd_una) salti++;
       }
       for(j=0;j<(block[i].length_queue-salti) && salti;j++)
          block[i].queue[j]=block[i].queue[j+salti];
       block[i].length_queue=block[i].length_queue-salti;
      //Se finestra si svuota invio dati
       while((block[i].snd_nxt-block[i].snd_una)<30 && (block[i].data_sent<block[i].sock->snd_offset)){ //FINESTRA PROVVISORIA PER PROVARE
          int a_window=30-(block[i].snd_nxt-block[i].snd_una);
          int dati=block[i].sock->snd_offset-block[i].data_sent;
          int lunghezza;
          if(dati>=6 && a_window>=6) lunghezza=6;
          else{
           if(dati>a_window) lunghezza=a_window;
           else
           lunghezza=dati;
          }
          crea_eth(eth,mymac,gateway,0x0800);
          crea_ip(ip,20+lunghezza,6,htonl(block[i].connection.foreign_ip));
          block[i].pshe.tcp_len=htons(20+lunghezza);
          crea_tcp(tcp,&block[i],0x10,lunghezza,block[i].snd_buffer);
          t=sendto(3,buffer,14+40+lunghezza,0,(struct sockaddr*)&sll,sizeof(sll));
          if(t==-1){
             perror("Send Fallita");
             exit(1);
          }
          //Inserisco Segment in coda di Ritrasmissione
          block[i].queue[block[i].length_queue].seq_number=block[i].snd_nxt;
          block[i].queue[block[i].length_queue].lunghezza=lunghezza;
          struct timeval time;
          gettimeofday(&time,NULL);
          timeradd(&time,&timeout,&(block[i].queue[block[i].length_queue].timeout));
          block[i].length_queue++;

          block[i].snd_nxt=block[i].snd_nxt+lunghezza;
          block[i].data_sent=block[i].data_sent+lunghezza;

     }
    }
   }   



}
// NON HO LA CONNESSIONE NEL TCB CONTROLLO SE è UNA NUOVA   
 
    
    for(i=0;i<LISTENING_SOCKETS;i++){
    
     if(htons(tcp->d_port)==listening[i]->local_port){ 
        if(tcp->flags==0x2){
         //FACCIO UN NUOVO SOCKET 
	 struct mysocket * sock=malloc(sizeof(struct mysocket));	
	
         sock->local_address=*(unsigned int*)myip;
         sock->foreign_address=ip->src;
         sock->local_port=htons(tcp->d_port);
         sock->foreign_port=htons(tcp->s_port);	 
	 sock->connection=CONN_NUMBER;
         
         sock->reader=0;     
         sock->last=0;      
         sock->snd_offset=0;
                 
 
	 listening[i]->list[listening[i]->number]=sock;
	 listening[i]->number=listening[i]->number+1;
        	 
         block[CONN_NUMBER].sock=sock;
         block[CONN_NUMBER].snd_buffer=sock->snd_buffer;
         block[CONN_NUMBER].rcv_buffer=sock->rcv_buffer;
         block[CONN_NUMBER].last=block[CONN_NUMBER].rcv_buffer;
      
         block[CONN_NUMBER].connection.foreign_port=htons(tcp->s_port);
         block[CONN_NUMBER].connection.foreign_ip=htonl(ip->src);
         block[CONN_NUMBER].connection.local_port=htons(tcp->d_port);
         block[CONN_NUMBER].connection.myip=htonl(*(unsigned int*)myip);
         
	 block[CONN_NUMBER].rcv_next=htonl(tcp->seq)+1;
         block[CONN_NUMBER].IRS=htonl(tcp->seq); 
         block[CONN_NUMBER].head==NULL;        
 
	 block[CONN_NUMBER].ISS=0xAAAAAAAA;
         block[CONN_NUMBER].length_queue=0;
         block[CONN_NUMBER].snd_nxt=block[CONN_NUMBER].ISS;
         block[CONN_NUMBER].snd_una=block[CONN_NUMBER].ISS;

         //Pseudoheader TCP
         block[CONN_NUMBER].pshe.src=*((unsigned int*)myip);  
         block[CONN_NUMBER].pshe.dst=(ip->src);
         block[CONN_NUMBER].pshe.protocol=htons(6);
         block[CONN_NUMBER].pshe.tcp_len=htons(20);
         
         //Mando SYN+ACK	 
	 crea_eth(eth,mymac,gateway,0x0800);
         crea_ip(ip,20,6,htonl(block[CONN_NUMBER].connection.foreign_ip));
         crea_tcp(tcp,&block[CONN_NUMBER],0x12,0,NULL);
         
         block[CONN_NUMBER].queue[block[CONN_NUMBER].length_queue].seq_number=block[CONN_NUMBER].ISS;
         block[CONN_NUMBER].queue[block[CONN_NUMBER].length_queue].lunghezza=0;
         struct timeval time;
         gettimeofday(&time,NULL);
         timeradd(&time,&timeout,&(block[CONN_NUMBER].queue[block[CONN_NUMBER].length_queue].timeout));
         block[CONN_NUMBER].length_queue++;

         block[CONN_NUMBER].snd_nxt++;
         block[CONN_NUMBER].conn_state=SYN_RCVD; 
         block[CONN_NUMBER].sock->socket_state=SOCK_CONNECTING;
         CONN_NUMBER++;
           
	 stampabytes((unsigned char*) ip,40); 
         t=sendto(3,buffer,54,0,(struct sockaddr*) &sll,sizeof(sll)); 
         if (t == -1 ){
            perror("Send Fallita");
            exit(1);
            }
        }
     }
    }
}


int main(){
int a,s,t,len,s2,i;
/******************************************
|                                         | 
|      CARICAMENTO FILE IN MEMORIA        |
|                                         |
*****************************************/    
FILE * file;
char dest[5000];
int length=0;
char b;

if((file=fopen("prova.txt","r"))==NULL)
printf("File Non Aperto");

while((b=fgetc(file))!=EOF){
dest[length++]=(unsigned char)b;
}
fclose(file);

printf("La lunghezza del file è %d\n",length);

/*************************************************|  
|                  SETTAGGI TIMER                 |
|*************************************************/
struct sigaction act;
act.sa_handler=NULL;
act.sa_sigaction=&handler;
act.sa_flags=SA_SIGINFO;
sigemptyset(&act.sa_mask);

struct itimerspec its;
timer_t timer;
its.it_value.tv_sec=0;
its.it_interval.tv_sec=0;
its.it_value.tv_nsec=100000000;
its.it_interval.tv_nsec=100000000;

s2=timer_create(CLOCK_REALTIME,NULL,&timer);
if(s2==-1) perror("Timer fallito");

//Stampo l'ID del Timer Generale
printf("Retransmission Timer ID %lx\n",(long) timer);
//Setto Timer
timer_settime(timer,0,&its,NULL);

s2=sigaction(SIGALRM,&act,NULL);
if(s2==-1) perror("Sigaction fallita");
//Setto il timeout per i pacchetti, ora 100ms
timeout.tv_sec=0;
timeout.tv_usec=100000;
/*************************************************************|
|              SETTAGGI SOCKET,STRUCT,PUNTATORI               |
|*************************************************************/
s=socket(AF_PACKET,SOCK_RAW,htons(0x0800));
if(s==-1){
  perror("Errore Socket");
  return 1;
  }
unsigned char buffer[1500];
struct eth_frame * eth;
struct ip_datagram *ip;
struct  tcp_segment *tcp;

eth=(struct eth_frame*) buffer;
ip=(struct ip_datagram*) eth->payload;
tcp=(struct tcp_segment*) ip->payload;

struct header {
char * n;
char * v;
};
struct header h[100];

/***********************************************************|
|              SETTAGGI SIGACTION SIGIO                     |
|***********************************************************/  

struct sigaction act2;
act2.sa_handler=NULL;
act2.sa_sigaction=&handler_sigio;
act2.sa_flags=SA_SIGINFO;
sigemptyset(&act2.sa_mask);

s2=sigaction(SIGRTMIN+1,&act2,NULL);
if(s2==-1) perror("Sigaction fallita");

fcntl(s,F_SETOWN,getpid());
fcntl(s,F_SETFL,fcntl(s,F_GETFL,NULL)|O_ASYNC);
fcntl(s,F_SETSIG,SIGRTMIN+1);
/******MAIN VERO E PROPRIO********************/

////////////////////CLIENT

struct mysocket ab;
int z,j,primiduepunti;
char *request_line;

myconnect(&ab,9000,80,*((unsigned int *)myip),*((unsigned int *)googleip));

char request[10000];
char response[100];
sprintf(response,"HEAD / HTTP/1.1\r\nConnection: close\r\n\r\n");

mywrite(&ab,response,38);

h[0].n=request;
request_line=h[0].n;
h[0].v=h[0].n;
for(z=0,j=0; myread(&ab,request+z,1);z++){
if ((z>1) && (request[z]=='\n') && (request[z-1]=='\r')){
           primiduepunti=1;
           request[z-1]=0;
           if(h[j].n[0]==0) break;
           h[++j].n=request+z+1;
           }
           if (primiduepunti && (request[z]==':')){
                h[j].v = request+z+1;
                request[z]=0;
                primiduepunti=0;
        }
}

printf("RESPONSE LINE: %s \n",request_line);
for(z=1;z<j;z++)
        printf("%s ===> %s\n",h[z].n,h[z].v);

myclose(&ab);
       
/////////////////SERVER
/*
struct list_socket ab;

mybind(&ab,12000);

mylisten(&ab);

struct mysocket * arrivo=myaccept(&ab);

char request[10000];
int z,j,primiduepunti;
char *request_line;

h[0].n=request;
request_line=h[0].n;
h[0].v=h[0].n;
for(z=0,j=0; myread(arrivo,request+z,1);z++){
if ((z>1) && (request[z]=='\n') && (request[z-1]=='\r')){
           primiduepunti=1;
           request[z-1]=0;
           if(h[j].n[0]==0) break;
           h[++j].n=request+z+1;
           }
           if (primiduepunti && (request[z]==':')){
                h[j].v = request+z+1;
                request[z]=0;
                primiduepunti=0;
        }
}

printf("REQUEST LINE: %s \n",request_line);
for(z=1;z<j;z++)
        printf("%s ===> %s\n",h[z].n,h[z].v);

char buf[100];
sprintf(buf,"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n1234");
mywrite(arrivo,buf,strlen(buf));


myclose(arrivo);
*/
while(1) sleep(200);
}

//*******METODI USER************************
int myconnect(struct mysocket* sock,unsigned short local_port,unsigned short foreign_port,unsigned int myip,unsigned int foreign_ip){
  //Preparazione
  int t,i;
  unsigned char buffer[1500];
  struct eth_frame * eth;
  struct ip_datagram *ip;
  struct  tcp_segment *tcp;

  eth=(struct eth_frame*) buffer;
  ip=(struct ip_datagram*) eth->payload;
  tcp=(struct tcp_segment*) ip->payload;
    
  //Riempimento Socket
  sock->local_address=htonl(myip);
  sock->foreign_address=htonl(foreign_ip);
  sock->local_port=htons(local_port);
  sock->foreign_port=htons(foreign_port);
  sock->socket_state=SOCK_CONNECTING;

  sock->last=0;
  sock->reader=0;

  //Riempimento TCB e Invio SYN
  block[CONN_NUMBER].sock=sock;
  block[CONN_NUMBER].snd_buffer=sock->snd_buffer;
  block[CONN_NUMBER].rcv_buffer=sock->rcv_buffer;
  block[CONN_NUMBER].last=block[CONN_NUMBER].rcv_buffer;
  block[CONN_NUMBER].length_queue=0; 
  block[CONN_NUMBER].rcv_next=0;
  block[CONN_NUMBER].rcv_wnd=BUF_SIZE;
 
  block[CONN_NUMBER].connection.foreign_ip=sock->foreign_address;
  block[CONN_NUMBER].connection.myip=sock->local_address;
  block[CONN_NUMBER].connection.local_port=htons(sock->local_port);
  block[CONN_NUMBER].connection.foreign_port=htons(sock->foreign_port);

  block[CONN_NUMBER].ISS=0xAAAAAAAA;
  block[CONN_NUMBER].snd_una=block[CONN_NUMBER].ISS;
  block[CONN_NUMBER].snd_nxt=block[CONN_NUMBER].ISS;
  //PseudoHeader
  block[CONN_NUMBER].pshe.src=htonl(block[CONN_NUMBER].connection.myip);
  block[CONN_NUMBER].pshe.dst=htonl(block[CONN_NUMBER].connection.foreign_ip);
  block[CONN_NUMBER].pshe.protocol=htons(6);
  block[CONN_NUMBER].pshe.tcp_len=htons(20);

  crea_eth(eth,mymac,gateway,0x0800);
  crea_ip(ip,20,6,htonl(block[CONN_NUMBER].connection.foreign_ip));
  crea_tcp(tcp,&block[CONN_NUMBER],0x2,0,NULL);

  t=sendto(3,buffer,14+40,0,(struct sockaddr*)&sll,sizeof(sll));
  if(t==-1){
       perror("SendFallita");
       exit(1);
  }

  //Metto SYN in coda di Ritrasmissione
  block[CONN_NUMBER].queue[block[CONN_NUMBER].length_queue].seq_number=block[CONN_NUMBER].ISS;
  block[CONN_NUMBER].queue[block[CONN_NUMBER].length_queue].lunghezza=0;
  struct timeval time;
  gettimeofday(&time,NULL);
  timeradd(&time,&timeout,&(block[CONN_NUMBER].queue[block[CONN_NUMBER].length_queue].timeout));
  block[CONN_NUMBER].length_queue++;
  
  block[CONN_NUMBER].snd_nxt++;
  block[CONN_NUMBER].conn_state=SYN_SENT;
  sock->connection=CONN_NUMBER;
  CONN_NUMBER++;

  while(sock->socket_state!=SOCK_CONNECTED)pause();
  return 0;
}

int mywrite(struct mysocket *sock,char * buffer, int count){
  //Preparazione
  int t,i,data_sent;
  unsigned char pacchetto[1500];
  struct eth_frame * eth;
  struct ip_datagram *ip;
  struct  tcp_segment *tcp;

  eth=(struct eth_frame*) pacchetto;
  ip=(struct ip_datagram*) eth->payload;
  tcp=(struct tcp_segment*) ip->payload;
  
  //Data Nel Sending Socket
  memcpy(sock->snd_buffer,buffer,count);
  sock->snd_offset=sock->snd_offset+count;
  sock->socket_state=SOCK_SENDING;
 
  char trap=0; 
  //Invio
  i=sock->connection;
  if(block[i].conn_state==ESTABLISHED){
    while((block[i].snd_nxt-block[i].snd_una)<30 && (block[i].data_sent<block[i].sock->snd_offset)){ //FINESTRA PROVVISORIA PER PROVARE
       if(trap!=1){
       crea_eth(eth,mymac,gateway,0x0800);
       crea_ip(ip,26,6,htonl(block[i].connection.foreign_ip));
       block[i].pshe.tcp_len=htons(26);
       crea_tcp(tcp,&block[i],0x10,6,block[i].snd_buffer);
       t=sendto(3,pacchetto,14+40+6,0,(struct sockaddr*)&sll,sizeof(sll));
       if(t==-1){
          perror("Send Fallita");
          exit(1);
       }}
       block[i].queue[block[i].length_queue].seq_number=block[i].snd_nxt;
       block[i].queue[block[i].length_queue].lunghezza=6;
       struct timeval time;
       gettimeofday(&time,NULL);
       timeradd(&time,&timeout,&(block[i].queue[block[i].length_queue].timeout));
       block[i].length_queue++;
       
       block[i].snd_nxt=block[i].snd_nxt+6;
       block[i].data_sent=block[i].data_sent+6;
       trap++;
       }
    }

  
}

int myread(struct mysocket *sock,char *buffer, int count){
  //printf("Last:%x Reader:%x \n",(int)a->last,(int)a->reader);

  while(((sock->last)-(sock->reader))<count) pause();

  memcpy(buffer,sock->rcv_buffer+sock->reader,count);
  sock->reader=sock->reader+count;
  return count;
}



int myclose(struct mysocket *sock){
  int t,i;
  unsigned char buffer[1500];
  struct eth_frame * eth;
  struct ip_datagram *ip;
  struct  tcp_segment *tcp;

  eth=(struct eth_frame*) buffer;
  ip=(struct ip_datagram*) eth->payload;
  tcp=(struct tcp_segment*) ip->payload;

  sock->socket_state=SOCK_CLOSING;

  i=sock->connection;
  if(block[i].data_sent==block[i].sock->snd_offset){ 
    
     write(1,"MANDO FIN\n",10);
     crea_eth(eth,mymac,gateway,0x0800);
     crea_ip(ip,20,6,htonl(block[i].connection.foreign_ip));
     block[i].pshe.tcp_len=htons(20);
     crea_tcp(tcp,&block[i],0x11,0,NULL);

     t=sendto(3,buffer,54,0,(struct sockaddr*)&sll,sizeof(sll));
     if(t==-1){
       perror("Send Fallita");
       exit(1);
     }
     block[i].snd_nxt++;
     block[i].fin_sent=1;
  }
  if(block[i].conn_state==ESTABLISHED) 
       block[i].conn_state=FIN_WAIT_1;
}

int mybind(struct list_socket *sock,unsigned short local_port){

  sock->local_port=local_port;
  sock->socket_state=SOCK_CLOSED;
  sock->number=0;
  return 0;
}


int mylisten(struct list_socket * sock){
  
  sock->socket_state=SOCK_LISTENING;
   
  listening[LISTENING_SOCKETS]=sock;
  LISTENING_SOCKETS++;
  return 0;
}  

struct mysocket * myaccept(struct list_socket *a){
 
  struct mysocket *sock;
  while (a->number==0) pause();
  while (a->list[0]->socket_state!=SOCK_CONNECTED) pause();
  write(1,"Prendo Socket\n",14); 
  sock=a->list[0];
  for(int i=0;i<a->number;i++)
         a->list[i]=a->list[i+1];
  a->number=a->number-1;

  return sock;
    
}


//Creazione frame Ethernet
void crea_eth(struct eth_frame *e, unsigned char *src, unsigned char *dest,unsigned short type){
  e->type=htons(type);
  int i;
  for(i=0;i<6;i++) e->src[i]=mymac[i];
  for(i=0;i<6;i++) e->dst[i]=dest[i];
}
//Creazione Ip Datagram
void crea_ip(struct ip_datagram *ip,int payloadlen,unsigned char proto,unsigned int dst){
  ip->ver_ihl=0x45;
  ip->tos=0;
  ip->totlen=htons(20+payloadlen);
  ip->id=htons(0x1234);
  ip->flags_off=htons(0);
  ip->ttl=128;
  ip->protocol=proto;
  ip->checksum=0;
  ip->src=*((unsigned int*) myip);
  ip->dst=dst;
  ip->checksum=htons(checksum((unsigned char*) ip,20));
}
//Creazione TCP Segment
void crea_tcp(struct tcp_segment* tcp,struct tcb * block,unsigned char flags,int data,char *buffer){
  tcp->s_port=htons(block->connection.local_port);
  tcp->d_port=htons(block->connection.foreign_port);
  tcp->seq=htonl(block->snd_nxt);
  tcp->ack=htonl(block->rcv_next);
  tcp->data_offs=0x50;
  tcp->flags=flags;
  tcp->window=htons(block->rcv_wnd);
  tcp->urgent_pointer=htons(0);
  if(buffer!=NULL){
    memcpy(tcp->payload,buffer+block->snd_nxt-0xAAAAAAAB,data);
  }
  tcp->checksum=htons(0);
  tcp->checksum=htons(checksum_tcp((unsigned char*)tcp,(unsigned char*) &block->pshe,20+data));
}

void retr_tcp(struct tcp_segment* tcp,struct tcb * block,unsigned int seq,unsigned char flags,int data,char *buffer){
  tcp->s_port=htons(block->connection.local_port);
  tcp->d_port=htons(block->connection.foreign_port);
  tcp->seq=htonl(seq);
  tcp->ack=htonl(block->rcv_next);
  tcp->data_offs=0x50;
  tcp->flags=flags;
  tcp->window=htons(5000);
  tcp->urgent_pointer=htons(0);
  if(buffer!=NULL){
    memcpy(tcp->payload,buffer+seq-0xAAAAAAAB,data);
  }
  tcp->checksum=htons(0);
  tcp->checksum=htons(checksum_tcp((unsigned char*)tcp,(unsigned char*) &block->pshe,20+data));
}


//Checksum IP
unsigned short checksum(unsigned char * buffer, int len){
  int i;
  unsigned short *p;
  unsigned int tot=0;
  p=(unsigned short*) buffer;
  for(i=0;i<len/2;i++){
        tot=tot+htons(p[i]);
        if (tot&0x10000) tot=(tot&0xFFFF)+1;
  }
  return (unsigned short)0xFFFF-tot;
}
//Checksum TCP
unsigned short checksum_tcp(unsigned char* buffer, unsigned char *pheader, int len){
  int i;
  unsigned short *p,*q;
  unsigned int tot=0;
  p=(unsigned short *)buffer;
  q=(unsigned short *) pheader;
  int newlen=len;
  if (len % 2){
       newlen++;
       buffer[len]=0;
  }

  for (i=0;i<newlen/2;i++){
      tot=tot+htons(p[i]);
      if (tot&0x10000) tot=(tot&0xFFFF)+1;
      }
  for (i=0;i<6;i++){
      tot=tot+htons(q[i]);
      if(tot&0x10000) tot=(tot&0xFFFF)+1;
      }
  return (unsigned short)0xFFFF-tot;
}

//Stampabytes Pacchetti
void stampabytes(unsigned char * buffer,int quanti){
  int i;
  for (i=0;i<quanti;i++){
     if(!(i&0x3)) printf("\n");
     printf("%.2X(%3d) ",buffer[i],buffer[i]);
     }
  printf("\n");
}


int push(struct tcb *block,int offset,int seq,int lunghezza){
 if(block->head==NULL){
   block->head=malloc(sizeof(struct fragment));
   printf("Malloc %lx\n",block->head);
   block->head->seq_number=seq;
   block->head->lunghezza=lunghezza;
   block->head->next=NULL;
   block->head->offset=offset;
   return 0;
 }
 struct fragment * temp=block->head;
 while((temp->seq_number+temp->lunghezza)<=seq && temp->next!=NULL) temp=temp->next;

 if(temp->next!=NULL || temp->seq_number+temp->lunghezza > seq){
   struct fragment *nuovo=malloc(sizeof(struct fragment));
   nuovo->seq_number=temp->seq_number;
   nuovo->lunghezza=temp->lunghezza;
   nuovo->next=temp->next;
   nuovo->offset=temp->offset;
   temp->seq_number=seq;
   temp->lunghezza=lunghezza;
   temp->next=nuovo;
   temp->offset=offset;
   }
 else{ 
   temp->next=malloc(sizeof(struct fragment));
   temp->next->seq_number=seq;
   temp->next->lunghezza=lunghezza;
   temp->next->offset=offset;
   temp->next->next=NULL;
   } 
 return 0;
}

int free_queue(struct tcb *block){
 //printf("LAST %d OFFSET %d \n",block->sock->last,block->head->offset);
 while(block->sock->last==block->head->offset){
   block->rcv_next=block->rcv_next+block->head->lunghezza;
   block->sock->last=block->sock->last+block->head->lunghezza;
   if(block->sock->last>BUF_SIZE) block->sock->last -=BUF_SIZE;
  
   struct fragment * temp=block->head;
   block->head=block->head->next;
   free(temp);
   if(block->head==NULL)break;
}   
  return 0;
}

