# burplog4xsssniper
调用xsssniper批量测试burpsuite导出日志文件中的接口

# 概念说明: 

xsssniper  是一个命令行式的XSS接口注入测试工具, 使用如下格式: 

xsssniper -u "http://172.16.10.128/dvwa/vulnerabilities/xss_s/"  --post --data="txtName=abc&mtxMessage=edf"  --cookie="security=low; PHPSESSID=2095d2b1f95"

burpsuite  是一个用于渗透测试的常用工具, 其导出的日志经常被用于 sqlmap 的批量测试, 其日志生成方法为:

options  --   misc --  logging  --  proxy ---  request     保存成文件



# 使用方法:

1 ) 确保 xsssniper 已经安装并能够执行

2 ) 将 burpsuite 的接口日志文件改名为 testit 存放于同级 burplog4xsssniper 目录

3 ) 执行 python burplog4xsssniper.py

4 ) 最终注入成功信息位于:  inject.log

