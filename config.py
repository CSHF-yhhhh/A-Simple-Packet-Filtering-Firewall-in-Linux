# -*- encoding: utf-8 -*-
"""
@文件:config.py
@作者: CSHF[https://github.com/CSHF-yhhhh]
@说明: 防火墙的配置文件
在运行之前,先将通目录下的 write.c 编译成write.so, 命令为 gcc write.c -shared -o write.so
"""

import ctypes
import subprocess
import threading

# 加载C模块
C_WRITE = ctypes.cdll.LoadLibrary("./write.so")


def __OpenDev(path="/dev/cshfFirewall"):
    """
    说明: 连接驱动
    args{
        path: 驱动路径
    }
    return: 驱动的文字描述符
    """
    dev = C_WRITE.OpenDev(ctypes.c_char_p(bytes(path, "utf-8")))
    if dev < 0:  # 打开设备失败
        print("Failed to open the device...", dev)
        return -1
    else:
        return dev


def __WriteLineToDev(dev, msg):
    """
    说明: 
    args{
        dev: 驱动的文件描述符
        msg: 需要写的信息
    }
    return: 成功写入的字节, 小于0则写入失败
    """

    rst = C_WRITE.WriteDev(dev, ctypes.c_char_p(bytes(msg, "utf-8")))
    if rst < 0:
        print("Failed to write [{}].".format(msg.replace("\n", "")))
    else:
        print("Successed to write [{}].".format(msg.replace("\n", "")))
    return rst


def __CloseDev(dev):
    """
    说明: 
    args{
        dev: 驱动的文件描述符
    }
    return: None
    """
    C_WRITE.CloseDev(dev)


# 全局配置字典
config = {
    "filter_mode": "",  # 过滤模式 blacklist whitelist
    "filter_rules": [],  # 过滤规则列表
    "log_tag": "[cshfFirewall]:",  # 内核日志输出的标签
    "log_quit": False,
}
config["log_tag_len"] = len(config["log_tag"])  # 该标签的长度
__config_lock = threading.Lock()
protocol_map = {"1": "ICMP", "6": "TCP", "17": "UDP"}


def ReadConfig(call_back, set_title):
    # 读取日志
    __config_lock.acquire()
    config_file = open("config.txt", "r")
    config_data = config_file.readlines()
    config_file.close()
    config["filter_mode"] = config_data.pop(0).replace("\n", "")
    config["filter_rules"].clear()
    set_title(config["filter_mode"])
    for line_str in config_data:
        new_line = line_str.split(" ")
        new_line[-1] = new_line[-1].replace("\n", "")
        if call_back:
            call_back(new_line)
        config["filter_rules"].append(new_line)
    print(config["filter_rules"])
    __config_lock.release()


def SaveConfig(f_mod):
    """
    说明: 保存配置,并将配置写入驱动
    args{
        f_mod: blacklist or whitelist
    }
    return: 
    """

    # 保存配置, 每次保存配置,清空防火墙的规则,然后重新写入规则
    __config_lock.acquire()
    config["filter_mode"] = f_mod
    config_file = open("config.txt", "w")
    dev = __OpenDev()  # 连接驱动
    __WriteLineToDev(dev, "c" + "\n")  # 清除原有配置
    config_file.write(config["filter_mode"] + "\n")
    __WriteLineToDev(dev, config["filter_mode"] + "\n")  # 设置过滤模式
    for rule in config["filter_rules"]:
        rule_msg = "{} {} {} {} {} {}\n".format(*rule)
        config_file.write(rule_msg)
        __WriteLineToDev(dev, rule_msg)  # 写入每一条配置
    config_file.close()
    __CloseDev(dev)
    __config_lock.release()


def addConfig(
    ftype="1", protocol="1", src="0.0.0.0", dst="0.0.0.0", sport="0", dport="0"
):
    # 添加一条规则, 如果存在则返回0, 成功返回1
    rule = list()
    rule.append(str(ftype))
    rule.append(str(protocol))
    rule.append(str(src))
    rule.append(str(dst))
    rule.append(str(sport))
    rule.append(str(dport))
    __config_lock.acquire()
    if rule in config["filter_rules"]:
        __config_lock.release()
        return 0
    else:
        config["filter_rules"].append(rule)
        __config_lock.release()
        SaveConfig(config["filter_mode"])  # 保存配置
        return 1


def GetLog(call_back=None):
    """
    说明: 获取日志
    args{
        call_back: 将内核输出传到call_back
    }
    return: 
    """

    output = subprocess.Popen("journalctl -f", shell=True, stdout=subprocess.PIPE)
    for ol in iter(output.stdout.readline, "b"):
        if config["log_quit"]:
            return
        ol = str(ol)
        i = ol.find(config["log_tag"])
        if i >= 0:
            msg = ol[i + config["log_tag_len"] :].replace("\\n'", "")
            """ with open("firewall.log", "a")as f:
                f.write(msg + "\n")
                f.close() """
            if call_back:
                call_back(msg + "\n")


def FirewallStatus():
    """
    说明: 得到防火墙的状态,若已经开启则返回1 否则返回0
    args{
        
    }
    return: 
    """

    out_put = subprocess.run(
        ["lsmod"], encoding="utf-8", shell=True, stdout=subprocess.PIPE
    ).stdout
    # print(out_put)
    if "firewall" in out_put:
        return 1
    else:
        return 0


def StartFirewall():
    """
    说明: 开启防火墙
    args{
        
    }
    return: 
    """

    if not FirewallStatus():
        subprocess.run(["insmod", "/home/cshf/code/firewall-master/firewall.ko"])
        SaveConfig(config["filter_mode"])


def StopFirewall():
    """
    说明: 关闭防火墙
    args{
        
    }
    return: 
    """
    subprocess.run(["rmmod", "firewall.ko"])

