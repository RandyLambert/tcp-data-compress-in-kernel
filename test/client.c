#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

int main(){
    //创建套接字
    int cli_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    // int cli_sock1 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    int flag=1;
    int len=sizeof(int);  

    // 设置 sockopt
    // int a = 5;
    // int ret = setsockopt(sock, SOL_TCP, TCP_FASTOPEN, &a, sizeof(int));
    // if ret != 0 {
    //     perror("error setting");
    // }

    //向服务器（特定的IP和端口）发起请求
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));  //每个字节都用0填充
    serv_addr.sin_family = AF_INET;  //使用IPv4地址
    // serv_addr.sin_addr.s_addr = inet_addr("192.168.56.26");  //具体的IP地址
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    serv_addr.sin_port = htons(1234);  //端口
    
    // client 绑定端口
    struct sockaddr_in cli_addr;
    cli_addr.sin_family = AF_INET;
    cli_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    cli_addr.sin_port = htons(12345);

    //向服务器（特定的IP和端口）发起请求
    // struct sockaddr_in serv_addr1;
    // memset(&serv_addr1, 0, sizeof(serv_addr1));  //每个字节都用0填充
    // serv_addr1.sin_family = AF_INET;  //使用IPv4地址
    // serv_addr1.sin_addr.s_addr = inet_addr("127.0.0.1");  //具体的IP地址
    // serv_addr1.sin_port = htons(1234);  //端口
    
    // client 绑定端口
    // struct sockaddr_in cli_addr1;
    // cli_addr1.sin_family = AF_INET;
    // cli_addr1.sin_addr.s_addr = inet_addr("127.0.0.1");
    // cli_addr1.sin_port = htons(12345);

    
    if(setsockopt(cli_sock, SOL_SOCKET, SO_REUSEADDR, &flag, len) == -1)  
    {  
        perror("setsockopt1");  
        exit(1);  
    }  

    if(setsockopt(cli_sock, SOL_SOCKET, SO_REUSEPORT, &flag, len) == -1)  
    {  
        perror("setsockopt2");  
        exit(1);  
    } 

    // if(setsockopt(cli_sock1, SOL_SOCKET, SO_REUSEADDR, &flag, len) == -1)  
    // {  
    //     perror("setsockopt1");  
    //     exit(1);  
    // }  

    // if(setsockopt(cli_sock1, SOL_SOCKET, SO_REUSEPORT, &flag, len) == -1)  
    // {  
    //     perror("setsockopt2");  
    //     exit(1);  
    // }  
 

    // if(bind(cli_sock, (struct sockaddr*)&cli_addr, sizeof(cli_addr)) == -1){
    //     perror("bind");  
    //     exit(1); 
    // }

    if(connect(cli_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1){
        perror("connect");  
        exit(1);  
    }

    // bind(cli_sock1, (struct sockaddr*)&cli_addr1, sizeof(cli_addr1));

    // connect(cli_sock1, (struct sockaddr*)&serv_addr1, sizeof(serv_addr1));
   
    while(1) {
        //读取服务器传回的数据
        char buffer[40];
        char buffer1[40];
        char str[] = "Hello Server!!!!!!!!!!!!!!!!!!!!!";

        // read(cli_sock, buffer, sizeof(buffer)-1);
        // read(cli_sock1, buffer1, sizeof(buffer1)-1);

        // printf("Message form server: %s\n", buffer);
        // printf("Message form server1: %s\n", buffer1);

        // write(cli_sock, str, sizeof(str));

        sleep(5);
    }

    //关闭套接字
    close(cli_sock);
    return 0;
}