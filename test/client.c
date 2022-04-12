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
    int sock = socket(AF_INET, SOCK_STREAM, 0);
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
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");  //具体的IP地址
    serv_addr.sin_port = htons(1234);  //端口
    connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));
   
    while(1) {
        //读取服务器传回的数据
        char buffer[40];
        read(sock, buffer, sizeof(buffer)-1);
    
        printf("Message form server: %s\n", buffer);
        // sleep(5);
    }

    //关闭套接字
    close(sock);
    return 0;
}