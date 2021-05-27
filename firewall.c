#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/time.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/if.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/semaphore.h>
#include <linux/cdev.h>

#define DEVICE_NAME "cshfFirewall"
#define CLASS_NAME "fire"
#define MAX_FILTER_DATA_NUM 100 //黑白名单的最大条数

//定义过滤类型
#define MY_FILTER_PROTOCOL 0b00000001
#define MY_FILTER_SRC_IP 0b00000010
#define MY_FILTER_DST_IP 0b00000100
#define MY_FILTER_SRC_PORT 0b00001000
#define MY_FILTER_DST_PORT 0b00010000

// 驱动的基本信息设置
MODULE_LICENSE("GPL");
/* @MODULE_LICENSE 中可选参数列表
"GPL" 是指明了 这是GNU General Public License的任意版本
“GPL v2” 是指明 这仅声明为GPL的第二版本
"GPL and addtional"
"Dual BSD/GPL"
"Dual MPL/GPL"
"Proprietary" 私有的, 除非你的模块显式地声明一个开源版本，否则内核会默认你这是一个私有的模块(Proprietary)。
*/
MODULE_AUTHOR("CSHF");                                       // 作者姓名
MODULE_DESCRIPTION("Packet filtering firewall(v1.0) @CSHF"); //驱动描述信息
MODULE_VERSION("1.0");                                       // 驱动的版本号

static char *name = "ٌWorld";
module_param(name, charp, S_IRUGO);                               // 设置变量的访问权限, 使用 S_IRUGO 作为参数可以被所有人读取
MODULE_PARM_DESC(name, "use 'journalctl -f' to read log output"); // 对模块的参数添加描述

// 驱动相关信息的变量
static struct semaphore sem; //信号量,用于同步
static struct timespec time; // 用于存放时间
static int majorNumber;      // 驱动的设备号
static char message[256] = {0};
static struct class *cshfFirewallClass = NULL;   // 设备驱动程序的结构指针
static struct device *cshfFirewallDevice = NULL; // 设备驱动程序设备结构指针

// 字符驱动程序的函数声明
static int open_dev(struct inode *, struct file *);    // 启动驱动
static int release_dev(struct inode *, struct file *); // 结束驱动

static ssize_t write_dev(struct file *, const char *, size_t, loff_t *); // 驱动写文件

//备在内核中表示为文件结构,为 file_operations 结构
static struct file_operations fops = {
    //这里可以添加需要的配置,可添加类型查看 file_operations 结构
    .open = open_dev,
    .write = write_dev,
    .release = release_dev,
};

//声明 钩子(包过滤) 函数
unsigned int packet_filter_hook(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *));

// 设置 钩子(包过滤) 函数
static struct nf_hook_ops hook_drop __read_mostly = {
    .pf = NFPROTO_IPV4,                     // 要拦截的ip类型
    .priority = NF_IP_PRI_FIRST,            // 优先级
    .hooknum = NF_INET_LOCAL_IN,            // 在哪个位置拦截包
    .hook = (nf_hookfn *)packet_filter_hook // 处理函数
};
/* @hooknum 的可选字段
NF_IP_PRE_ROUTING(在收到数据包之后)
NF_IP_LOCAL_IN(发送到网络栈的数据包)
NF_IP_FORWARD(应该被转发的报文)
NF_IP_POST_ROUTING(通过路由并准备发送的包)
NF_IP_LOCAL_OUT(来自我们自己的网络堆栈的数据包)
*/

// 过滤相关变量
//过滤规则结构体定义
typedef struct filter_data
{
    int type;              //过滤类型(0b00001.协议 0b00010.源IP 0b00100.目的IP 0b01000.源端口 0b10000.目的端口)
    unsigned int protocol; //协议类型 {1: ICMP, 6: TCP, 17: UDP}
    unsigned int src;      //源IP
    unsigned int dst;      //目的IP
    unsigned int src_port; //源端口号
    unsigned int dst_port; //目的端口号
} F_DATA, filter_data;
int b_or_w;                                   //标识当前是添加到白名单还是黑名单(0写到黑名单, 1写到白名单)
int data_type;                                //标识添加的类型
int filter_data_num;                          // 过滤条数
F_DATA filter_data_list[MAX_FILTER_DATA_NUM]; //过滤列表

// LKM 的初始化函数 return 0 则初始化成功
static int __init firewall_init(void)
{
    int ret;
    sema_init(&sem, 1); // 初始化信号量
    printk(KERN_INFO "[cshfFirewall]: Hello %s!", name);

    //为设备动态分配设备号
    majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
    if (majorNumber < 0)
    {
        printk(KERN_ERR "[cshfFirewall]: Failed to register a major number ");
        return majorNumber;
    }
    printk(KERN_INFO "[cshfFirewall]: Registered correctly with major number %d", majorNumber);

    //注册设备类
    cshfFirewallClass = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(cshfFirewallClass)) // 如果有错误则清除错误
    {
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ERR "[cshfFirewall]: Failed to register Device class");
        return PTR_ERR(cshfFirewallClass); //在指针上返回错误的正确方法
    }
    printk(KERN_INFO "[cshfFirewall]: Device class registered successfully");

    //注册设备驱动程序
    cshfFirewallDevice = device_create(cshfFirewallClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
    if (IS_ERR(cshfFirewallDevice)) //清除错误
    {
        class_destroy(cshfFirewallClass);
        unregister_chrdev(majorNumber, DEVICE_NAME);
        printk(KERN_ERR "[cshfFirewall]: Failed to create the device");
        return PTR_ERR(cshfFirewallDevice);
    }
    printk(KERN_INFO "[cshfFirewall]: device class created correctly");

    ret = nf_register_net_hook(&init_net, &hook_drop); //注册钩子函数
    if (ret)
        printk(KERN_INFO "FAILED");

    // 初始化过滤设置
    filter_data_num = 0;
    b_or_w = 0;
    data_type = 1;
    return ret;
}

// LKM 的退出函数, 清理空间,注销函数
static void __exit firewall_exit(void)
{
    device_destroy(cshfFirewallClass, MKDEV(majorNumber, 0));
    class_unregister(cshfFirewallClass);
    class_destroy(cshfFirewallClass);
    unregister_chrdev(majorNumber, DEVICE_NAME);
    printk(KERN_INFO "[cshfFirewall]: Bye %s from the cshfFirewall! module unloaded", name);

    nf_unregister_net_hook(&init_net, &hook_drop);
}

//设备驱动启动函数
static int open_dev(struct inode *inodep, struct file *filep)
{
    printk(KERN_ALERT "[cshfFirewall]: ****************************************************");
    printk(KERN_INFO "[cshfFirewall]: Device has been opened ");
    down(&sem);
    return 0;
}

// 驱动关闭函数
static int release_dev(struct inode *inodep, struct file *filep)
{
    printk(KERN_INFO "cshfFirewall: Device successfully closed");
    up(&sem);
    return 0;
}

unsigned int ip_str_to_num(const char *buf)
{
    /*
    将字符串格式的IP转换成十进制整数型IP
    args{
        buf: ip字符串
    }
    */
    unsigned int tmpip[4] = {0};
    unsigned int tmpip32 = 0;

    sscanf(buf, "%d.%d.%d.%d", &tmpip[0], &tmpip[1], &tmpip[2], &tmpip[3]);

    tmpip32 = (tmpip[3] << 24) | (tmpip[2] << 16) | (tmpip[1] << 8) | tmpip[0];

    return tmpip32;
}

static inline void ip_num_to_str(unsigned int ip_num, char *ip_str)
{
    /*
    将十进制整数型IP转换成字符串型IP
    args{
        ip_num: 十进制数的IP
        ip_str: 将转换后的字符串存储于
    }
    */
    unsigned char *uip = (unsigned char *)&ip_num;
    snprintf(ip_str, 17, "%d.%d.%d.%d", uip[0], uip[1], uip[2], uip[3]);
}

/*设备写函数
在这里处理防火墙规则
每次只会读取一行函数(结尾为一行)
写入配置的规则:[]内的为写入的信息
    [blacklist]: 将过滤模式设置为 黑名单, 如果设置前为 白名单 ,则清空配置
    [whitelist]: 将过滤模式设置为 白名单, 如果设置前为 黑名单 ,则清空配置
    [type protocol src_str dst_str src_port dst_port]: 6个参数,分别为{
        注: 每个参数使用 空格 隔开
                type: 过滤类型{十进制数
                        MY_FILTER_PROTOCOL  0b00000001  按照协议过滤
                        MY_FILTER_SRC_IP    0b00000010  源IP过滤
                        MY_FILTER_DST_IP    0b00000100  目的IP过滤
                        MY_FILTER_SRC_PORT  0b00001000  源端口过滤
                        MY_FILTER_DST_PORT  0b00010000  目标端口过滤
                        输入为10进制数, 可任意组合,如 过滤协议和源IP 则将此项设置为 0b000011
                        }
                protocol:   协议类型{十进制数
                    1: ICMP
                    6: TCP
                    17: UDP
                }
                src_str:    源IP{完整的点分十进制的IP
                    如果无需配置,请设置为 0.0.0.0
                    如果需要配置,请设置为 127.0.0.1 等类似IP
                }
                dst_str:    目的IP{完整的点分十进制的IP
                    如果无需配置,请设置为 0.0.0.0
                    如果需要配置,请设置为 127.0.0.1 等类似IP
                }
                src_port:   源端口{十进制整数的端口号
                    如果无需配置,请设置为 0
                    如果需要配置,请设置为 80 等类似端口
                }
                dst_port:   目标端口{十进制整数的端口号
                    如果无需配置,请设置为 0
                    如果需要配置,请设置为 80 等类似端口
                }
            }
*/
static ssize_t write_dev(struct file *filep, const char *buffer, size_t len, loff_t *offset)
{
    int error_count = 0;

    error_count = copy_from_user(message, buffer, len);
    switch (message[0])
    {
    case 'b': // 设置接下来的信息添加到黑名单
        if (b_or_w == 1)
            filter_data_num = 0; //清空防火墙现有规则
        b_or_w = 0;
        printk(KERN_NOTICE "[cshfFirewall]: SET MODE BLACKLIST", message);
        break;
    case 'w': //设置接下来的信息添加到白名单
        if (b_or_w == 0)
            filter_data_num = 0; //清空防火墙现有规则
        b_or_w = 1;
        printk(KERN_NOTICE "[cshfFirewall]: SET MODE WHITELIST", message);
        break;
    case 'c':
        filter_data_num = 0;
        break;
    default:
        message[len] = '\0';
        //待添加检验是否有重复
        unsigned int type;
        unsigned int protocol;
        char src_str[25];
        char dst_str[25];
        unsigned int src_port;
        unsigned int dst_port;
        sscanf(message, "%d %d %s %s %d %d", &type, &protocol, src_str, dst_str, &src_port, &dst_port);
        filter_data_list[filter_data_num].type = type;
        filter_data_list[filter_data_num].protocol = protocol;
        filter_data_list[filter_data_num].src = ip_str_to_num(src_str);
        filter_data_list[filter_data_num].dst = ip_str_to_num(dst_str);
        filter_data_list[filter_data_num].src_port = src_port;
        filter_data_list[filter_data_num].dst_port = dst_port;
        ++filter_data_num;
        if (b_or_w)
        {
            printk(KERN_NOTICE "[cshfFirewall]: Add rule(Blacklist) [Type: %d] [Prorocol: %d] [SourceIP: %s] [DestinationIP: %s] [SourcePort: %d] [DestinationPort: %d]", type, protocol, src_str, dst_str, src_port, dst_port);
        }
        else
        {
            printk(KERN_NOTICE "[cshfFirewall]: Add rule(Whitelist) [Type: %d] [Prorocol: %d] [SourceIP: %s] [DestinationIP: %s] [SourcePort: %d] [DestinationPort: %d]", type, protocol, src_str, dst_str, src_port, dst_port);
        }
        break;
    }
    return len;
}

//防火墙的钩子函数,拦截到数据包后进行判断处理
unsigned int packet_filter_hook(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{

    struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
    struct udphdr *udp_header;
    struct tcphdr *tcp_header;

    unsigned int src_ip = (unsigned int)ip_header->saddr;
    unsigned dest_ip = (unsigned int)ip_header->daddr;
    unsigned int src_port = 0;
    unsigned int dest_port = 0;

    int i;
    int flag = 0; //用于标明这个包是否符合规则
    char SOurce[25];
    char src[20];
    char dst[20];
    bool _protocol, _src, _dst, _srcp, _dstp;

    if (!skb)
        return NF_DROP;

    getnstimeofday(&time);
    //printk(KERN_INFO "[cshfFirewall]: received packet at time : %.2lu:%.2lu:%.2lu ", (time.tv_sec / 3600) % 24, (time.tv_sec / 60) % 60, (time.tv_sec) % 60);
    if (ip_header->protocol == 17)
    {
        udp_header = (struct udphdr *)skb_transport_header(skb);
        src_port = (unsigned int)ntohs(udp_header->source);
        //printk(KERN_DEBUG "[cshfFirewall]: (UDP)IP addres = %pI4(%u)  DEST = %pI4", &src_ip, src_port, &dest_ip);
    }
    else if (ip_header->protocol == 6)
    {
        tcp_header = (struct tcphdr *)skb_transport_header(skb);
        src_port = (unsigned int)ntohs(tcp_header->source);
        dest_port = (unsigned int)ntohs(tcp_header->dest);
        //printk(KERN_DEBUG "[cshfFirewall]: (TCP)IP addres = %pI4(%u)  DEST = %pI4", &src_ip, src_port, &dest_ip);
    }

    //snprintf(SOurce, 25, "%pI4:%u", &ip_header->saddr, src_port);
    ip_num_to_str(src_ip, src);  //得到点分10进制的源IP
    ip_num_to_str(dest_ip, dst); //得到点分10进制的目标IP
    printk(KERN_ALERT "[cshfFirewall]: ****************************************************");
    printk(KERN_ALERT "[cshfFirewall]: Received a packet.Packet_INFO{[protocol:%d][src_ip:%s][dst_ip:%s][src_port:%d][dst_port:%d]}", ip_header->protocol, src, dst, src_port, dest_port);
    if (!b_or_w)
    {
        //黑名单过滤
        printk(KERN_DEBUG "[cshfFirewall]: ---- Blacklist Filtering");
        for (i = 0; i < filter_data_num; i++)
        {
            //因为可以任意组合,所以每个过滤类型都要检验一次
            flag = 0;
            _protocol = _src = _dst = _srcp = _dstp = false;
            if ((filter_data_list[i].type & MY_FILTER_PROTOCOL) == MY_FILTER_PROTOCOL) //是否设置了协议过滤
            {
                if (filter_data_list[i].protocol == ip_header->protocol) //匹配到协议
                {
                    flag += MY_FILTER_PROTOCOL;
                    _protocol = true;
                }
            }
            if ((filter_data_list[i].type & MY_FILTER_SRC_IP) == MY_FILTER_SRC_IP)
            {
                if (filter_data_list[i].src == src_ip)
                {
                    flag += MY_FILTER_SRC_IP;
                    _src = true;
                }
            }
            if ((filter_data_list[i].type & MY_FILTER_DST_IP) == MY_FILTER_DST_IP)
            {
                if (filter_data_list[i].dst == dest_ip)
                {
                    flag += MY_FILTER_DST_IP;
                    _dst = true;
                }
            }
            if ((filter_data_list[i].type & MY_FILTER_SRC_PORT) == MY_FILTER_SRC_PORT)
            {
                if (filter_data_list[i].src_port == src_port)
                {
                    flag += MY_FILTER_SRC_PORT;
                    _srcp = true;
                }
            }
            if (ip_header->protocol == 6 && (filter_data_list[i].type & MY_FILTER_DST_PORT) == MY_FILTER_DST_PORT)
            {
                if (filter_data_list[i].dst_port == dest_port)
                {
                    flag += MY_FILTER_DST_PORT;
                    _dstp = true;
                }
            }
            if (flag == filter_data_list[i].type)
            {
                printk(KERN_ALERT "[cshfFirewall]: ---- DROPED {Matching: %s %s %s %s %s}", (_protocol ? " [PROTOCOL] " : " "), (_src ? " [SOURCE IP] " : " "), (_dst ? " [DESTINATION IP] " : " "), (_srcp ? " [SOURCE PORT] " : " "), (_dstp ? " [DESTINATION PORT] " : " "));
                return NF_DROP;
            }
        }
        printk(KERN_ALERT "[cshfFirewall]: ---- ACCEPT");
        return NF_ACCEPT;
    }
    else
    { //白名单过滤
        printk(KERN_DEBUG "[cshfFirewall]: ---- Whitelist Filtering");
        for (i = 0; i < filter_data_num; i++)
        {
            //因为可以任意组合,所以每个过滤类型都要检验一次
            flag = 0;
            _protocol = _src = _dst = _srcp = _dstp = false;
            if ((filter_data_list[i].type & MY_FILTER_PROTOCOL) == MY_FILTER_PROTOCOL) //是否设置了协议过滤
            {
                if (filter_data_list[i].protocol == ip_header->protocol) //匹配到协议
                {
                    flag += MY_FILTER_PROTOCOL;
                    _protocol = true;
                }
            }
            if ((filter_data_list[i].type & MY_FILTER_SRC_IP) == MY_FILTER_SRC_IP)
            {
                if (filter_data_list[i].src == src_ip)
                {
                    flag += MY_FILTER_SRC_IP;
                    _src = true;
                }
            }
            if ((filter_data_list[i].type & MY_FILTER_DST_IP) == MY_FILTER_DST_IP)
            {
                if (filter_data_list[i].dst == dest_ip)
                {
                    flag += MY_FILTER_DST_IP;
                    _dst = true;
                }
            }
            if ((filter_data_list[i].type & MY_FILTER_SRC_PORT) == MY_FILTER_SRC_PORT)
            {
                if (filter_data_list[i].src_port == src_port)
                {
                    flag += MY_FILTER_SRC_PORT;
                    _srcp = true;
                }
            }
            if (ip_header->protocol == 6 && (filter_data_list[i].type & MY_FILTER_DST_PORT) == MY_FILTER_DST_PORT)
            {
                if (filter_data_list[i].dst_port == dest_port)
                {
                    flag += MY_FILTER_DST_PORT;
                    _dstp = true;
                }
            }
            if (flag == filter_data_list[i].type)
            {
                printk(KERN_ALERT "[cshfFirewall]: ---- ACCEPTED {Matching: %s %s %s %s %s}", (_protocol ? " [PROTOCOL] " : " "), (_src ? " [SOURCE IP] " : " "), (_dst ? " [DESTINATION IP] " : " "), (_srcp ? " [SOURCE PORT] " : " "), (_dstp ? " [DESTINATION PORT] " : " "));
                return NF_ACCEPT;
            }
        }
        printk(KERN_ALERT "[cshfFirewall]: ---- DROPED");
        return NF_DROP;
    }
}

module_init(firewall_init);
module_exit(firewall_exit);