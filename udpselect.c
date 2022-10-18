#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>

int main(int argc, char **argv){
  int sockfd = socket(AF_INET,SOCK_DGRAM,0);

  struct sockaddr_in serveraddr,clientaddr;
  serveraddr.sin_family=AF_INET;
  serveraddr.sin_port=htons(9876);
  serveraddr.sin_addr.s_addr=INADDR_ANY;

  bind(sockfd,(struct sockaddr*)&serveraddr,
       sizeof(serveraddr));

  fd_set myfds;
  FD_SET(sockfd,&myfds);
  FD_SET(STDIN_FILENO,&myfds);
  
  while(1){
    fd_set tmp=myfds;
    int nn=select(FD_SETSIZE,&tmp,NULL,NULL,NULL);
    if(FD_ISSET(sockfd,&tmp)){
      printf("Got something on the socket\n");
      int len = sizeof(clientaddr);
      char line[5000];
      int n = recvfrom(sockfd,line,5000,0,
		       (struct sockaddr*)&clientaddr,&len);
      printf("%s\n",line);
    }
    if(FD_ISSET(STDIN_FILENO,&tmp)){
      printf("The user typed something, I better do something with it\n");
      char buf[5000];
      fgets(buf,5000,stdin);
      printf("You typed %s\n",buf);
    }
    

  }
}
