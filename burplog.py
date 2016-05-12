# -*- coding: utf-8-*-  

import os

############################## color print

class Logger:                                                                      
        HEADER = '\033[95m'                                                        
        OKBLUE = '\033[94m'                                                        
        OKGREEN = '\033[92m'                                                       
        WARNING = '\033[93m'                                                       
        FAIL = '\033[91m'                                                          
        ENDC = '\033[0m'                                                           
                                                                                   
        @staticmethod                                                              
        def log_normal(info):                                                      
                print(Logger.OKBLUE + info + Logger.ENDC)                          
                                                                                   
        @staticmethod                                                              
        def log_high(info):                                                        
                print(Logger.OKGREEN + info + Logger.ENDC)                          
                                                                                   
        @staticmethod                                                              
        def log_fail(info):                                                        
                print(Logger.FAIL + info + Logger.ENDC)



#############################  xsssniper


def xsssniperlog(outfile):   ##日志的处理

	###  这里需要过滤

	#    中间文件位置
	tempfile="./output.log"

	f = open(tempfile)             
	line = f.readline() 
	logs=""

	while line: 

		####
		line=line.replace('\n','')
		if len(line)>1:      #除去换行

			### 具体注入信息  连取三行     
			if line[:38]=="[+] RESULT: Found XSS Injection points":
				line = f.readline() 
				logs=logs+line

				line = f.readline() 			
				logs=logs+line
				
				line = f.readline() 
				logs=logs+line	

				line = f.readline() 
				logs=logs+line

				logs=logs+'\n'


		####
		line = f.readline() 

	f.close()  

	## 写入文件
	output = open(outfile, 'w')
	output.write(logs)
	output.close()

	## 最终回显
	Logger.log_high(logs)
	Logger.log_normal("Log file: "+outfile)


def xsssniper(allpath,data,cookie,tempfile):    ### 扫描

	#xsssniper -u "http://172.16.10.128/dvwa/vulnerabilities/xss_s/"  --post --data="txtName=abc&mtxMessage=edf&btnSign=Sign+Guestbook"  --cookie="security=low; PHPSESSID=2095d2b1f9551221955e1abeaeda12f1"

	command="xsssniper -u " + allpath

	if len(data)>0:
		command=command+" --post --data=" +data

	if len(cookie)>0:
		command=command+" --cookie=" +cookie		

	print(command)
	
	command=command+ " >> " + tempfile     ## 输出到文件
	resp = os.system(command)


#############################

if __name__=="__main__":  

	#    日志位置
	logfile="./testit"

	#   协议类别
	pro="http"   #  http  https

	#    最终文件位置
	outfile="./inject.log"

	#############################  处理日志

	f = open(logfile)             
	line = f.readline()  

	pos=0   # 日志标记位

	allpath=""
	cookie=""
	data=""

	#    中间文件位置
	tempfile="./output.log"
	os.system("rm " + tempfile)

	Logger.log_normal("Please wait .....")

	while line: 

		####
		line=line.replace('\n','')
		if len(line)>1:      #除去换行

			### 地址信息
			if line[:4]=="GET ":
				line=line.replace("GET ","")
				line=line.replace(" HTTP/1.1","")
				addr=line			

			### HOST
			if line[:6]=="Host: ":
				line=line.replace("Host: ","")
				line=pro+"://"+line	
				host=line							

			### cookie
			if line[:8]=="Cookie: ":
				line=line.replace("Cookie: ","")
				cookie='"' + line + '"'   ### cookie


			### post 数据
			if line[:16]=="Content-Length: ":
				line = f.readline() 				
				line = f.readline() 
				line=line.replace('\n','')
				data='"' + line + '"'    ### data

			### 文件处理标记位
			if line[:54]=="======================================================":
				pos=pos+1

			if pos==3:

				####  一次完整的记录完成

				allpath='"' + host+addr +'"'    ### 完整链接
				
				'''
				print(allpath)
				print(data)
				print(cookie)

				print(' ')
				'''

				####  这里调用对应的函数

				Logger.log_normal("Scanning .....")

				xsssniper(allpath,data,cookie,tempfile)

				#### 恢复初始化
				pos=0
				allpath=""
				cookie=""
				data=""

		####

		line = f.readline() 

	f.close()  


	######  日志的输出处理

	Logger.log_normal("\n")
	Logger.log_normal("Result : ")

	xsssniperlog(outfile)


	Logger.log_normal("\n")






