/**
 * 网络主机扫描程序 - 使用ICMP协议检测网络中的活动主机
 * 
 * 本程序通过发送ICMP Echo请求(ping)来检测指定IP范围内的活动主机
 * 用法: ./scanhost Start_IP End_IP
 */



#include <iostream>     // 标准输入输出流
#include <string>       // 字符串处理
#include <vector>       // 向量容器
#include <sstream>      // 字符串流
#include <sys/socket.h> // 套接字API
#include <netinet/in.h> // 网络地址结构
#include <netinet/ip.h> // IP协议定义
#include <netinet/ip_icmp.h> // ICMP协议定义
#include <arpa/inet.h>  // IP地址转换函数
#include <netdb.h>      // 网络数据库操作
#include <unistd.h>     // UNIX标准函数
#include <sys/time.h>   // 时间相关结构体
#include <errno.h>      // 错误码定义

/**
 * ICMP数据包头部结构定义
 * ICMP头部共8个字节，包含类型、代码、校验和、标识符和序列号
 */
typedef struct _ICMP_HEADER {
    uint8_t type;      // 类型字段: 8表示回送请求(Echo Request)，0表示回送应答(Echo Reply)
    uint8_t code;      // 代码字段: 回送请求和回送应答均为0
    uint16_t checksum; // 校验和: 用于检测数据在传输过程中是否发生错误
    uint16_t id;       // 标识符: 用于唯一标识该ICMP数据包，通常使用进程ID
    uint16_t seq;      // 序列号: 用于匹配请求和响应
} ICMP_HEADER;

/**
 * 计算ICMP数据包的校验和
 * 
 * @param buffer 待计算校验和的数据缓冲区
 * @param size 数据大小(字节)
 * @return 计算出的校验和
 */
uint16_t checksum(uint16_t* buffer, int size) {
    unsigned long cksum = 0; // 校验和累加器
    
    // 以16位(2字节)为单位累加
    while (size > 1) {
        cksum += *buffer++; // 累加当前16位，并将指针移至下一个16位
        size -= sizeof(uint16_t);
    }
    
    // 如果数据长度为奇数，需要处理最后一个字节
    if (size) {
        cksum += *(uint8_t*)buffer;
    }
    
    // 将高16位累加到低16位
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16); // 处理可能的进位
    
    return (uint16_t)(~cksum); // 返回校验和的反码
}

/**
 * 将点分十进制IP地址转换为无符号长整型
 * 
 * @param ip 点分十进制IP地址字符串(如 "192.168.1.1")
 * @return 无符号长整型表示的IP地址
 */
unsigned long ip_to_ulong(const std::string& ip) {
    unsigned long a, b, c, d; // 存储IP地址的四个部分
    char ch; // 用于存储分隔符'.'
    std::istringstream iss(ip);
    iss >> a >> ch >> b >> ch >> c >> ch >> d; // 解析IP地址
    return (a << 24) | (b << 16) | (c << 8) | d; // 组合为32位无符号长整型
}

/**
 * 将无符号长整型转换为点分十进制IP地址
 * 
 * @param ip 无符号长整型表示的IP地址
 * @return 点分十进制IP地址字符串
 */
std::string ulong_to_ip(unsigned long ip) {
    std::ostringstream oss;
    oss << ((ip >> 24) & 0xff) << "." // 提取最高字节(第一段)
        << ((ip >> 16) & 0xff) << "." // 提取次高字节(第二段)
        << ((ip >> 8) & 0xff) << "."  // 提取次低字节(第三段)
        << (ip & 0xff);               // 提取最低字节(第四段)
    return oss.str();
}

/**
 * 向指定IP地址发送ICMP回送请求并等待响应
 * 
 * @param ip 目标IP地址
 * @param timeout 等待响应的超时时间(毫秒)
 * @return 如果主机活动返回true，否则返回false
 */
bool ping(const std::string& ip, int timeout = 1000) {
    // 1. 创建原始套接字用于ICMP协议通信
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (sock < 0) {
        perror("socket() 失败");
        return false;
    }
    
    // 2. 设置接收超时
    struct timeval tv;
    tv.tv_sec = timeout / 1000;          // 秒
    tv.tv_usec = (timeout % 1000) * 1000; // 微秒
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    
    // 3. 准备目标地址结构
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &dest.sin_addr); // 将IP字符串转换为网络地址
    
    // 4. 构造ICMP回送请求数据包
    char icmp_packet[sizeof(ICMP_HEADER) + 32]; // ICMP头部 + 32字节数据
    memset(icmp_packet, 0, sizeof(icmp_packet));
    ICMP_HEADER* icmp_header = (ICMP_HEADER*)icmp_packet;
    icmp_header->type = ICMP_ECHO;   // 类型8: Echo请求
    icmp_header->code = 0;           // 代码0
    icmp_header->id = (uint16_t)getpid(); // 使用进程ID作为标识符
    icmp_header->seq = 0;            // 序列号从0开始
    icmp_header->checksum = 0;       // 先将校验和置0
    
    // 填充数据部分，使用'A'字符
    memset(icmp_packet + sizeof(ICMP_HEADER), 'A', 32);
    
    // 计算并设置校验和
    icmp_header->checksum = checksum((uint16_t*)icmp_packet, sizeof(icmp_packet));
    
    // 5. 发送ICMP回送请求
    if (sendto(sock, icmp_packet, sizeof(icmp_packet), 0, 
              (struct sockaddr*)&dest, sizeof(dest)) <= 0) {
        perror("sendto() 失败");
        close(sock);
        return false;
    }
    
    // 6. 接收响应
    char recv_buf[1024]; // 接收缓冲区
    struct sockaddr_in from;
    socklen_t from_len = sizeof(from);
    int ret = recvfrom(sock, recv_buf, sizeof(recv_buf), 0, (struct sockaddr*)&from, &from_len);
    close(sock); // 关闭套接字
    
    // 7. 处理接收结果
    if (ret <= 0) {
        // 未收到响应或出错
        return false;
    }
    
    // 8. 解析IP头部和ICMP头部
    struct ip* ip_header = (struct ip*)recv_buf;
    int ip_header_len = ip_header->ip_hl * 4; // IP头部长度，以4字节为单位
    
    // 检查接收的数据是否完整
    if (ret < ip_header_len + sizeof(ICMP_HEADER)) {
        return false;
    }
    
    // 提取ICMP头部
    ICMP_HEADER* recv_icmp = (ICMP_HEADER*)(recv_buf + ip_header_len);
    
    // 检查是否为ICMP回送应答(类型0)
    if (recv_icmp->type == ICMP_ECHOREPLY && recv_icmp->code == 0) {
        return true; // 收到有效的回送应答，主机活动
    }
    return false; // 其他响应，认为主机不活动
}

/**
 * 扫描指定IP范围内的活动主机
 * 
 * @param start_ip 起始IP地址
 * @param end_ip 结束IP地址
 */
void scan_hosts(const std::string& start_ip, const std::string& end_ip) {
    // 将IP地址转换为数值以便于遍历
    unsigned long start = ip_to_ulong(start_ip);
    unsigned long end = ip_to_ulong(end_ip);
    
    // 遍历IP范围
    for (unsigned long ip = start; ip <= end; ip++) {
        std::string current_ip = ulong_to_ip(ip);
        std::cout << "正在检查 " << current_ip << " ... ";
        std::cout << "发送ICMP回送请求(类型号为8) ... ";
        
        // 发送ping请求并打印结果
        if (ping(current_ip)) {
            std::cout << "收到ICMP回送应答(类型号为0)，活动主机" << std::endl;
        } else {
            std::cout << "无响应" << std::endl;
        }
    }
}

/**
 * 主函数 - 程序入口点
 * 
 * @param argc 命令行参数数量
 * @param argv 命令行参数数组
 * @return 程序退出状态码
 */
int main(int argc, char* argv[]) {
    // 检查命令行参数
    if (argc != 3) {
        std::cerr << "用法: " << argv[0] << " Start_IP End_IP" << std::endl;
        return 1; // 参数错误，返回非0值
    }
    
    // 开始扫描指定IP范围
    scan_hosts(argv[1], argv[2]);
    return 0; // 成功结束
}