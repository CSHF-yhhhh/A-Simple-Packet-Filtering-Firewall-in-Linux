# -*- encoding: utf-8 -*-
"""
@文件:user_firewall.py
@作者: CSHF[https://github.com/CSHF-yhhhh]
@说明: 用户的防火墙配置界面
"""

import tkinter
import tkinter.ttk as ttk
import tkinter.messagebox
import threading

from config import *


root = tkinter.Tk()  # 根控件
root.title("CSHF Firewall 1.0")
width = 950  # 窗口的宽度
height = 600  # 窗口的高度
max_x, max_y = root.winfo_screenwidth(), root.winfo_screenheight()
# 设置窗口居中
root.geometry(
    "%dx%d+%d+%d" % (width, height, (max_x - width) / 2, (max_y - height) / 2)
)

filter_id = tkinter.StringVar()
filter_type = tkinter.StringVar()
filter_protocol = tkinter.StringVar()
filter_src_ip = tkinter.StringVar()
filter_dst_ip = tkinter.StringVar()
filter_src_port = tkinter.StringVar()
filter_dst_port = tkinter.StringVar()
firewall_filter_type = tkinter.StringVar()

top_config_bar = tkinter.LabelFrame(root)
top_config_bar.pack(side=tkinter.TOP, fill=tkinter.Y)

start_btn = tkinter.Button(top_config_bar, text="启动防火墙", command=lambda: StartStop())
start_btn.pack(side=tkinter.LEFT, padx=5)
filter_type_combobox = ttk.Combobox(
    master=top_config_bar,
    values=["blacklist", "whitelist"],
    textvariable=firewall_filter_type,
    state="readonly",
    width=10,
)
filter_type_combobox.pack(side=tkinter.LEFT, padx=5)
rule_Box = tkinter.LabelFrame(root)
rule_Box.pack(side=tkinter.TOP, fill=tkinter.BOTH, expand=True)

title = tkinter.Label(rule_Box, text="过滤规则表")
title.pack(side=tkinter.TOP)

rule_edit = tkinter.LabelFrame(rule_Box)
rule_edit.pack(side=tkinter.TOP, fill=tkinter.X, expand=True)


first_line = tkinter.Frame(rule_edit)
first_line.pack(side=tkinter.TOP)
second_line = tkinter.Frame(rule_edit)
second_line.pack(side=tkinter.TOP)
tkinter.Label(first_line, text="ID").pack(side=tkinter.LEFT)
tkinter.Entry(first_line, textvariable=filter_id, state=tkinter.DISABLED, width=4).pack(
    side=tkinter.LEFT, padx=5
)
tkinter.Label(first_line, text="协议类型").pack(side=tkinter.LEFT)
ttk.Combobox(
    master=first_line,
    values=["ICMP", "TCP", "UDP", ""],
    textvariable=filter_protocol,
    state="readonly",
    width=8,
).pack(side=tkinter.LEFT, padx=5)
tkinter.Label(first_line, text="源IP地址").pack(side=tkinter.LEFT)
tkinter.Entry(first_line, textvariable=filter_src_ip).pack(side=tkinter.LEFT, padx=5)
tkinter.Label(first_line, text="目的IP地址").pack(side=tkinter.LEFT)
tkinter.Entry(first_line, textvariable=filter_dst_ip).pack(side=tkinter.LEFT, padx=5)
tkinter.Label(first_line, text="源端口").pack(side=tkinter.LEFT)
tkinter.Entry(first_line, textvariable=filter_src_port, width=6).pack(
    side=tkinter.LEFT, padx=5
)
tkinter.Label(first_line, text="目的端口").pack(side=tkinter.LEFT)
tkinter.Entry(first_line, textvariable=filter_dst_port, width=6).pack(
    side=tkinter.LEFT, padx=5
)
tkinter.Button(second_line, text="添加规则", command=lambda: AddRule()).pack(
    side=tkinter.LEFT, padx=5
)
tkinter.Button(second_line, text="删除选中规则", command=lambda: DeleteRule()).pack(
    side=tkinter.LEFT, padx=5
)
tkinter.Button(second_line, text="清空规则", command=lambda: DeleteAllRule()).pack(
    side=tkinter.LEFT, padx=5
)

container = tkinter.Frame(rule_Box)
container.pack(side=tkinter.TOP, fill=tkinter.BOTH, expand=True)

rule_scroll_y = tkinter.Scrollbar(container, orient=tkinter.VERTICAL)
rule_scroll_y.pack(side=tkinter.RIGHT, fill=tkinter.Y)
rule_tree = ttk.Treeview(
    container,
    columns=["ID", "类型", "协议", "源IP", "目的IP", "源端口", "目的端口"],
    show="headings",
    yscrollcommand=rule_scroll_y.set,
)
rule_tree.heading("ID", text="ID")
rule_tree.column("ID", anchor="center", width=20)
rule_tree.heading("类型", text="类型")
rule_tree.column("类型", anchor="center", width=50)
rule_tree.heading("协议", text="协议")
rule_tree.column("协议", anchor="center", width=50)
rule_tree.heading("源IP", text="源IP")
rule_tree.column("源IP", anchor="center", width=50)
rule_tree.heading("目的IP", text="目的IP")
rule_tree.column("目的IP", anchor="center", width=50)
rule_tree.heading("源端口", text="源端口")
rule_tree.column("源端口", anchor="center", width=50)
rule_tree.heading("目的端口", text="目的端口")
rule_tree.column("目的端口", anchor="center", width=50)
rule_tree.pack(fill=tkinter.BOTH, expand=True)
rule_scroll_y.config(command=rule_tree.yview)


Log_Box = tkinter.LabelFrame(root)
Log_Box.pack(side=tkinter.TOP, fill=tkinter.BOTH, expand=True)
tkinter.Label(Log_Box, text="日志信息[日志文件位置: {}]".format(__file__ + "/firewall.log")).pack(
    side=tkinter.TOP
)

Log_container = tkinter.Frame(Log_Box)
Log_container.pack(side=tkinter.TOP, fill=tkinter.BOTH, expand=True)
scroll_y = tkinter.Scrollbar(Log_container, orient=tkinter.VERTICAL)
scroll_y.pack(side=tkinter.RIGHT, fill=tkinter.Y)
log_text = tkinter.Text(
    master=Log_container, state=tkinter.DISABLED, yscrollcommand=scroll_y.set,
)
log_text.pack(side=tkinter.TOP, fill=tkinter.BOTH, expand=True)
scroll_y.config(command=log_text.yview)


def StartStop():
    """
    说明: 开启/关闭防火墙
    args{
        
    }
    return: 
    """

    if start_btn["text"] == "启动防火墙":
        StartFirewall()
        SaveConfig(config["filter_mode"])
        start_btn["text"] = "关闭防火墙"
    else:
        StopFirewall()
        start_btn["text"] = "启动防火墙"


def logWrite(*arg):
    """
    说明: 将参数写入log_text
    args{
        
    }
    return: 
    """

    # print(arg)
    log_text.configure(state=tkinter.NORMAL)
    msg = ""
    for s in arg:
        msg += " " + str(s)
    log_text.insert("end", msg)
    log_text.configure(state=tkinter.DISABLED)
    log_text.see(tkinter.END)


def ChangeBlackOrWhite(*args):
    """
    说明: 改变过滤模式
    args{
        
    }
    return: 
    """

    now_select = filter_type_combobox.selection_get()
    if now_select != config["filter_mode"]:
        if (
            tkinter.messagebox.askquestion(
                title="切换提醒", message="是否要将过滤模式切换为 {} ?\n(这会清空现有的规则)".format(now_select)
            )
            == "yes"
        ):
            config["filter_mode"] = now_select
            DeleteAllRule()


def OpenLog():
    """
    说明: 开启日志监听
    args{
        
    }
    return: 
    """

    threading.Thread(target=GetLog, args=(logWrite,)).start()


def __InsertRule(rule):
    """
    说明: 插入一条规则
    args{
        
    }
    return:
    """
    global protocol_map
    new_rule = list()
    t = int(rule[0])

    new_rule.append(len(rule_tree.get_children()) + 1)
    new_rule.append(rule[0])
    new_rule.append(protocol_map[rule[1]] if t & 0b00000001 else "")
    new_rule.append(rule[2] if t & 0b00000010 else "")
    new_rule.append(rule[3] if t & 0b00000100 else "")
    new_rule.append(rule[4] if t & 0b00001000 else "")
    new_rule.append(rule[5] if t & 0b00010000 else "")
    # new_rule.append(rule[6] if t & 0b00000001 else " ")
    rule_tree.insert("", "end", values=new_rule)


def __SetTitle(t):
    title["text"] = "过滤规则表[{}]".format(t)
    if t.lower() == "blacklist":
        firewall_filter_type.set("blacklist")
    else:
        firewall_filter_type.set("whitelist")


def __ClearTree():
    children = rule_tree.get_children()
    for child in children:
        rule_tree.delete(child)


def RuleTreeClickEvent(self, *args):
    item = rule_tree.selection()
    if len(item):
        select = rule_tree.item(item[0], "values")
        filter_id.set(select[0])
        filter_type.set(select[1])
        filter_protocol.set(select[2])
        filter_src_ip.set(select[3])
        filter_dst_ip.set(select[4])
        filter_src_port.set(select[5])
        filter_dst_port.set(select[6])


def AddRule():
    """
    说明: 添加规则
    args{
        
    }
    return: 
    """

    rule = list()
    f_type = 0
    invert_protocol_map = {"ICMP": "1", "TCP": "6", "UDP": "17"}
    t = filter_protocol.get()
    if t:
        f_type += 0b00000001
        rule.append(invert_protocol_map[t])
    else:
        rule.append("0")
    t = filter_src_ip.get()
    if t:
        f_type += 0b00000010
        rule.append(t)
    else:
        rule.append("0.0.0.0")
    t = filter_dst_ip.get()
    if t:
        f_type += 0b00000100
        rule.append(t)
    else:
        rule.append("0.0.0.0")
    t = filter_src_port.get()
    if t:
        f_type += 0b00001000
        rule.append(t)
    else:
        rule.append("0")
    t = filter_dst_port.get()
    if t:
        f_type += 0b00010000
        rule.append(t)
    else:
        rule.append("0")
    rule.insert(0, f_type)
    print(rule)
    if addConfig(*rule):
        __InsertRule(rule)
    else:
        tkinter.messagebox.showinfo(title="添加失败", message="添加失败, 已经存在该规则")


def DeleteRule():
    """
    说明: 删除选中规则
    args{
        
    }
    return: 
    """

    item = rule_tree.selection()
    if len(item):
        select = rule_tree.item(item[0], "values")
        # print(select)
        if (
            tkinter.messagebox.askquestion(
                title="删除提醒", message="是否要删除id为 {} 的规则?".format(select[0])
            )
            == "yes"
        ):
            rule = list()
            invert_protocol_map = {"ICMP": "1", "TCP": "6", "UDP": "17"}
            t = select[1]
            if t:
                rule.append(t)
            else:
                rule.append("0")
            t = select[2]
            if t:
                rule.append(invert_protocol_map[t])
            else:
                rule.append("0")
            t = select[3]
            if t:
                rule.append(t)
            else:
                rule.append("0.0.0.0")
            t = select[4]
            if t:
                rule.append(t)
            else:
                rule.append("0.0.0.0")
            t = select[5]
            if t:
                rule.append(t)
            else:
                rule.append("0")
            t = select[6]
            if t:
                rule.append(t)
            else:
                rule.append("0")
            print(rule, config["filter_rules"])
            if rule in config["filter_rules"]:
                config["filter_rules"].remove(rule)
            SaveConfig(config["filter_mode"])
            __ClearTree()
            ReadConfig(__InsertRule, __SetTitle)


def DeleteAllRule():
    """
    说明: 删除全部规则
    args{
        
    }
    return: 
    """

    __ClearTree()
    config["filter_rules"].clear()
    SaveConfig(config["filter_mode"])


def CloseWindows(*args):
    """
    说明: 
    args{
        关闭窗口的函数
    }
    return: 
    """

    config["log_quit"] = True

    root.destroy()


root.protocol("WM_DELETE_WINDOW", CloseWindows)  # 绑定关闭窗口函数
OpenLog()  # 开启日志监听
filter_type_combobox.bind("<<ComboboxSelected>>", ChangeBlackOrWhite)
rule_tree.bind("<ButtonRelease-1>", RuleTreeClickEvent)
ReadConfig(__InsertRule, __SetTitle)  # 加载初始配置

if FirewallStatus():  # 检查防火墙是否已经打开
    start_btn["text"] = "关闭防火墙"

root.mainloop()
