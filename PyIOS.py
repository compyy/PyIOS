#!/home/id961723/Python/ActivePython/bin/python3.4
"""
Author: Yasir Ashfaque
Date: 	06/03/2014
"""

from multiprocessing import Pool
import pexpect
import getpass
import time
import argparse
import sys, os
from argparse import RawTextHelpFormatter

##Doc Strings##
desc="""PyIOS is a custom python script to do ssh/telnet on CISCO routers and perform multiple tasks.
The Script runs in multiple modes:
It can run to implement/log the show/config sequential commands on the router.
It can run in Analyse mode where it needs to collect output of show commands/configurations from routers and apply logic to the data collected and generate desired output.

"""

u_help="""Define required Username to connect the hosts
	"""

m_help="""Defines host manually, otherwise host names will be taken from hosts.txt in same folder.
The formation of hosts in hosts.txt should be as following:
host1
host2
host3

"""
				
t_help=""" specify -t for Telnet the hosts, otherwise by default its SSH.
	"""

c_help="""Define the command manually in "" (Double Quote), otherwise it will load multiple lines command from cmd.cfg in same folder.
The formation of commands in cmd.cfg should be as following:
c1
c2
c3

"""

a_help="""Enables script to load cmdhost.txt file for hosts and specific commands to be applied on the hosts.(Dont use -m with -a and -c)
The formation of cmdhost.txt should be as described.
Hostname1:
c1
c2
c3
Hostname2:
c1
c2
c3

"""

p_help="""By Default Script will open 10 processes parallel, it can be increased to desired value by using this switch.
	"""
##end of Strings	

##Definging Execution Function##############

def openssh(username, password, hostname):
	ssh_newkey = "Are you sure you want to continue connecting (yes/no)?"
	constr = "ssh " + username + "@" + hostname
	ssh = pexpect.spawnu(constr)
	en_hostname = hostname + "#"
	ret = ssh.expect([pexpect.EOF, ssh_newkey, "[P|p]assword:"],timeout=120)
	
	if ret == 0:
		print ("Error Connecting to " + hostname +", May be host is not resolvable or not responding")
		return 0
	
	if ret == 1:
		ssh.sendline("yes")
		ret = ssh.expect([pexpect.TIMEOUT, "[P|p]assword:"])
		
		if ret == 0:
			print ("Could not accept new key from " + hostname + ", Try to do manual ssh first or remove the old key with ssh-keygen")
			return 0
	
	ssh.sendline(password)
	auth = ssh.expect(["[P|p]assword:", ">", en_hostname])
	
	if auth == 0:
		print ("On Host: " + hostname + ", The  "+  username + "\'s password provided is incorrect or TACACS is down")
		return 0
		
	if auth == 1:
		ssh.sendline("enable")
		ssh.expect("[pP]assword:")
		ssh.sendline(password)
		enable = ssh.expect(["[P|p]assword:", en_hostname])
		
		if enable == 0:
			print ("For " + hostname + " enable password is incorrect")
			return 0
	
	return ssh
			
    
def coderun(username, password, hostname,cmd):
	ssh = openssh(username, password, hostname)
	en_hostname = hostname + "#"
	
	if ssh!=0:
		logf = open("logs/" +hostname, "w")
		if type(cmd) == type("string"):
			ssh.sendline("terminal length 0")
			ssh.expect(en_hostname,timeout=120)
			ssh.sendline(cmd)
			ssh.expect(en_hostname,timeout=120)
			logf.write(ssh.before)
			
		else:
			ssh.sendline("terminal length 0")
			ssh.expect([en_hostname],timeout=120)
			for i in cmd:
				ssh.sendline(i.strip())
				ret = ssh.expect([pexpect.TIMEOUT,en_hostname],timeout=120)
				
				if ret==0:
					print ("Session Timed out on " + hostname + " Max Timeout is 120 Seconds, Script is Exiting...")
					logf.write(ssh.before)
					logf.write("\n")
					return 0
				
				if ret==1:
					logf.write(ssh.before)
					logf.write("\n")
					time.sleep(1)
		print ("CMD executed, on  " + hostname +" script is exiting..!")
		ssh.close()

def testrun(username, password, hostname,cmd):
	print (username)
	print (hostname)
	print (password)
	print (cmd)
	

##
if __name__ == "__main__":
	
	parser = argparse.ArgumentParser(description=desc,formatter_class=RawTextHelpFormatter)
	parser.add_argument("username", help=u_help)
	parser.add_argument("-m", dest="hostname", help=m_help)
	parser.add_argument("-t", dest="telnet", default=False, action='store_true', help=t_help)
	parser.add_argument("-c", dest="cmd", default=(open("cmd.cfg", "r")), help=c_help)
	parser.add_argument("-a", dest="adv", default=False, action='store_true', help=a_help)
	parser.add_argument("-p", dest="max_parallel", default=10, type=int, help=p_help)
	args = parser.parse_args()
	
	passwd = getpass.getpass("Enter Password: ")
#	print (args.username)
#	print (args.hostname)
#	print (args.cmd)
#	print (args.telnet)
#	print (args.adv)
#	print (args.max_parallel)
						
	
	#try:
	coderun(args.username, passwd, args.hostname, args.cmd)
	
#	except NameError:
#		host = [line.strip() for line in open("hosts.txt", "r")]
#		pool = Pool(max_parallel)
#		pool.map(testrun, args.username, 1)
#		pool.close()
#		pool.join()
#
##Functions end here, start of main code#####

# Start of code
