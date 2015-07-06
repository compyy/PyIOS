#! /usr/bin/python
"""
Author: Yasir Ashfaque
Date: 	06/03/2014
"""

from multiprocessing import Pool
import pexpect
import getpass
import time
import sys, getopt




##Definging Execution Function##############

def print_help():
	print("""
Usage: python PyIOS.py [OPTIONS]

PyIOS is a custom python script to do ssh/telnet on CISCO routers and perform multiple tasks.
The Script runs in multiple modes:
It can run to implement/log the show/config sequential commands on the router.
It can run in Analyse mode where it needs to collect output of show commands/configurations from routers and apply logic to the data collected and generate desired output.

Mandatory arguments to run the script.

	-u			Define User name to connect the hosts. 


Optional arguments to run the script.
	-t			For Telnet the hosts, otherwise by default its SSH.
	-p			By Default Script will open 10 processes parallel, it can be increased to desired value by using this switch.

	-m			Defines host manually, otherwise host names will be taken from hosts.txt in same folder.
				The formation of hosts in hosts.txt should be as following:
				host1
				host2
				host3

	-c 			Define the command manually in "" (Double Quote), otherwise it will load multiple lines command from cmd.cfg in same folder.
				The formation of commands in cmd.cfg should be as following:
				c1
				c2
				c3

	-a			Enables script to load cmdhost.txt file for hosts and specific commands to be applied on the hosts.(Dont use -m with -a and -c)
				The formation of cmdhost.txt should be as described.
				Hostname1:
				c1
				c2
				c3
				Hostname2:
				c1
				c2
				c3



	-h = For Help
""")

def openssh(host):
	ssh_newkey = 'Are you sure you want to continue connecting (yes/no)?'
	constr = 'ssh ' + user + '@' + host
	ssh = pexpect.spawn(constr)
	ret = ssh.expect([pexpect.EOF, ssh_newkey, '[P|p]assword:'],timeout=120)
	
	if ret == 0:
		print ('Error Connecting to ' + host +', May be host is not resolvable or not responding')
		return 0
	
	if ret == 1:
		ssh.sendline('yes')
		ret = ssh.expect([pexpect.TIMEOUT, '[P|p]assword:'])
		
		if ret == 0:
			print ('Could not accept new key from ' + host + ', Try to do manual ssh first or remove the old key with ssh-keygen')
			return 0
	
	ssh.sendline(passwd)
	auth = ssh.expect(['[P|p]assword:', '>', '#'])
	
	if auth == 0:
		print ('On Host: ' + host + ', The ' +  user + '\'s password provided is incorrect or TACACS is down')
		return 0
		
	if auth == 1:
		ssh.sendline('enable')
		ssh.expect('[pP]assword:')
		ssh.sendline(passwd)
		enable = ssh.expect(['[P|p]assword:', '#'])
		
		if enable == 0:
			print (host + ' enable password is incorrect')
			return 0
	
	return ssh
			
    
def coderun(host):
	ssh = openssh(host)
	cmd = open("cmd.cfg", "r")
	logf = open("logs/" +host, "w")
	
	if ssh!=0:
		ssh.sendline('terminal length 0')
	
		for i in cmd:
			ssh.sendline(i.strip())
			ret = ssh.expect([pexpect.TIMEOUT,'#'],timeout=120)
		
			if ret==0:
				print ("Session Timed out on " + host + " Max Timeout is 120 Seconds, Script is Exiting...")
				logf.write(ssh.before)
				logf.write("\n")
				return 0
		
			if ret==1:
				logf.write(ssh.before)
				logf.write("\n")
				time.sleep(1)
			
		print ("CMD executed, on  " + host +" script is exiting..!")
		ssh.close()

		


def main(argv):
	try:
		opts, args = getopt.getopt(argv,"hhelpu:c:m:a:t:p:")
		if not opts:
			print_help()
	
	except getopt.GetoptError:
		print_help()
		sys.exit(2)
	
	for opt, arg in opts:
		if opt in ("-h", "help"):
			print_help()
			
		elif opt == "-u":
			print(arg)
			
		
		elif opt == "-c":
			print(arg)
			
		
	sys.exit()
		
	#if host == "":
	#host = [line.strip() for line in open("hosts.txt", 'r')]
	
	#pool = Pool(len(host))
	#pool = Pool(10)
	#pool.map(coderun, host, 1)
	#pool.close()
	#pool.join()

##Functions end here, start of main code#####

# Start of code
#host = raw_input("Enter Hostname/IP or Leave Blank if you want to use hosts.txt: ")
#user = raw_input("Enter Username: ")
#passwd = getpass.getpass("Enter Password: ")

if __name__ == "__main__":
	main(sys.argv[1:])
