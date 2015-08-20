#!/usr/bin/env python3.4

'''
Author: Yasir Ashfaque
Date: 	06/03/2014
'''
#################

#################

##Doc Strings##
desc='''PyIOS is a custom python script to do ssh/telnet on CISCO routers and perform multiple tasks.
The Script runs in multiple modes:
It can run to implement/log the show/config sequential commands on the router.
It can run in Analyse mode where it needs to collect output of show commands/configurations from routers and apply logic to the data collected and generate desired output.

It requires Python 3.4+ and Pexpect 4.0+

'''

u_help='''Define required Username to connect the hosts

'''

m_help='''Defines host manually, otherwise host names will be taken from hosts.txt in same folder.
The formation of hosts in hosts.txt should be as following:
host1
host2
host3

'''
				
t_help='''Specify -t for Telnet the hosts, otherwise by default its SSH.(Under construction)

'''

child_help='''Specify -child with string to find config for specific child.

'''

f_help='''Specify -f and then specify the configurations you want to check.

'''

if_help='''Specify -if and follow by string, to verify if this feature/keyword has been enabled and what is the top parent.

'''
offline_help='''Specify -offline, if config file is already in logs/ folder and we just want to analyze specific config there.

'''
c_help='''Defines the command manually in '' (Double Quote), otherwise it will load multiple lines command from cmd.cfg in same folder.
The formation of commands in cmd.cfg should be as following:
c1
c2
c3

'''

a_help="""Enables script to load hostnames from filenames in folder hosts in same directory, and applies the cmd provided in those files.
(Dont use -m, -c with -a)


"""

p_help='''By Default Script will open 10 processes parallel, it can be increased to desired value by using this switch.

'''
##End of DOC Strings	

##Definging Classes & Execution Function##############

class pssh:
	'This is SSH class which opens ssh session to routers/switches and execute specific function'
	
	def __init__(self, hostname, username, password, cmd,child):
		self.hostname = hostname
		self.username = username
		self.password = password
		self.cmd = cmd
		self.child = child
		
	def displayStart(self):
		print ('Script is trying to login in to the ', self.hostname, '....!')

	def displayProgress(self):
		print ('Command is being executed on ', self.hostname, '....!')
	
	def displayEnd(self):
		print ('Script is exiting the ', self.hostname, '....!')
	
	def clear_rsakey(self):
		os.system('ssh-keygen -R ' + self.hostname)
		self.open_ssh()
		
	def open_ssh(self):
		ssh_newkey = 'Are you sure you want to continue connecting (yes/no)?'
		ssh_refused = 'port 22: Connection refused'
		ssh_unresolved = 'Could not resolve hostname'
		ssh_noroute = 'No route to host'
		ssh_hostkeyfailed = 'Host key verification failed'
		session = 'ssh ' + self.username + '@' + self.hostname
		self.ssh = pexpect.spawnu(session)
		self.displayStart()
		time.sleep(1)
		ret = self.ssh.expect([pexpect.EOF, ssh_newkey, '[P|p]assword:'],timeout=120)
		ssh_return = self.ssh.before
		
		if ret == 0:
			if (ssh_return.find(ssh_refused)) != -1:
				print ('Error Connecting to', self.hostname, ', Port 22 is blocked or SSH is not enabled !!')
				return 0
			elif(ssh_return.find(ssh_unresolved)) != -1:
				print ('Error Connecting to', self.hostname, ', Host is not resolvable, try to use IP instead of names !!')
				return 0
			elif(ssh_return.find(ssh_noroute)) != -1:
				print ('Error Connecting to', self.hostname, ', No route to host')
				return 0
			elif(ssh_return.find(ssh_hostkeyfailed)) != -1:
				print ('Error Connecting to', self.hostname, ', RSA Key Failed, reinitializing the key.')
				self.clear_rsakey()
			else:
				print ('Error Connecting to', self.hostname, ', Host is not responding, or other Issue (May require: Manual debugs to verify the issue) !!')
				return 0

		if ret == 1:
			self.ssh.sendline('yes')
			ret_key = self.ssh.expect([pexpect.TIMEOUT, '[P|p]assword:'])
		
			if ret_key == 0:
				print ('Could not accept new key from ', self.hostname, ', Try to do manual ssh first or remove the old key with ssh-keygen')
				return 0
			
			if ret_key == 1:
				ret = 2
		
		if ret == 2:
			self.ssh.sendline(self.password)
			auth = self.ssh.expect(['[P|p]assword:', '>', '#'])
			if auth == 0:
				print ('On Host: ', self.hostname, ', The  ',self.username, '\'s password provided is incorrect or TACACS is down')
				return 0
		
			elif auth == 1:
				self.ssh.sendline('enable')
				self.ssh.expect('[pP]assword:')
				self.ssh.sendline(self.password)
				enable = self.ssh.expect(['[P|p]assword:', '#'])
		
				if enable == 0:
					print ('For Host:', self.hostname, ', Enable password is incorrect')
					return 0
	
	def close_ssh(self):
		self.displayEnd()
		self.status = 0
		self.ssh.close()


def run_cmd(object):
	if (object.open_ssh()) != 0:
		object.displayProgress()
		logf = open('logs/' + object.hostname, 'w')
		
		if object.cmd !='advance' and object.cmd !='cmd-file':
			object.ssh.sendline('terminal length 0')
			object.ssh.expect('#',timeout=120)
			object.ssh.sendline(object.cmd)
			wait_for_prompt_log(object.ssh, '#', logf)
		
		else:
			if object.cmd == 'advance':
				cmd = open('hosts/' + object.hostname)
			else:
				cmd = open('cmd.cfg', 'r')
				
			object.ssh.sendline('terminal length 0')
			object.ssh.expect('#',timeout=120)
			for i in cmd:
				object.ssh.sendline(i.strip())
				wait_for_prompt_log(object.ssh, '#', logf)
				
		logf.close()
		object.close_ssh()
	
	else:
		print('Script could not open SSH session to host: ', object.hostname)
		
	

def find_config(object):
	if (object.open_ssh()) != 0:
		object.displayProgress()
		logf = open('temp/' + object.hostname + '.cfg', 'w')
		object.ssh.sendline('terminal length 0')
		object.ssh.expect('#',timeout=120)
		object.ssh.sendline(object.cmd)
		wait_for_prompt_log(object.ssh, '#', logf)
		logf.close()
		parse = CiscoConfParse('temp/' + object.hostname + '.cfg', syntax='ios')
		outf = open('logs/' + object.hostname, 'w')
		for obj in parse.find_objects(object.child):
			for i in obj.geneology_text:
				outf.write((i +'\n'))
		
		object.close_ssh()
		os.remove('temp/' + object.hostname + '.cfg')
		outf.close()
	
	else:
		print('Script could not open SSH session to host: ', object.hostname)

def run_ifanalysis(iftext):
	print ('Analyzing logs files for desired keyword....!')
	for i in os.listdir('logs/'):
		outf = open('analysis/' + i, 'w')
		parse = CiscoConfParse('logs/'+ i)
		for obj in parse.find_objects(iftext):
			for i in obj.geneology_text:
				outf.write((i +'\n'))
		outf.close()
	print ('Analyzing Done....!')

def wait_for_prompt_log(ssh, prompt,logf, timeout=1):
	gotprompt = 0
	while not gotprompt:
		ssh.expect(prompt, timeout=None)
		logf.write((ssh.before + '\n'))
		gotprompt = ssh.expect(['.', pexpect.TIMEOUT], timeout=timeout)

def wait_for_prompt(ssh, prompt,timeout=1):
	gotprompt = 0
	while not gotprompt:
		ssh.expect(prompt, timeout=None)
		gotprompt = ssh.expect(['.', pexpect.TIMEOUT], timeout=timeout)

###### start of main() #######
def main():
	parser = argparse.ArgumentParser(description=desc,formatter_class=RawTextHelpFormatter)
	parser.add_argument('username', help=u_help)
	parser.add_argument('-m', dest='hostname', default=[line.strip() for line in open('hosts.txt', 'r')],help=m_help)
	parser.add_argument('-t', dest='telnet', default=False, action='store_true', help=t_help)
	parser.add_argument('-c', dest='cmd', default='cmd-file', help=c_help)
	parser.add_argument('-p', dest='max_parallel', default=10, type=int, help=p_help)
	parser.add_argument('-f', dest='flag_find', default=False, action='store_true', help=f_help)
	parser.add_argument('-child', dest='child', default='none', help=child_help)
	parser.add_argument('-if', dest='if_analysis', default='none', help=if_help)
	parser.add_argument('-offline', dest='offline', default=False, action='store_true' , help=offline_help)
	parser.add_argument("-a", dest="adv", default=False, action='store_true', help=a_help)

	args = parser.parse_args()

	if args.offline is False:
		args.password = getpass.getpass('Enter Password: ')
		
		if args.adv is False:
			if type(args.hostname) is str:
				session_basic = pssh(args.hostname,args.username,args.password,args.cmd,args.child)
				if args.flag_find is True:
					find_config(session_basic)
				else:
					run_cmd(session_basic)
				
			else:
				session = list()
				for i in args.hostname:
					session.append(pssh(i,args.username, args.password,args.cmd,args.child))
				with concurrent.futures.ProcessPoolExecutor(max_workers=args.max_parallel) as executor:
					if args.flag_find is True:
						executor.map(find_config, session)
					else:
						executor.map(run_cmd, session)
		
		else:
			session = list()
			args.cmd= 'advance'
			for i in os.listdir('hosts/'):
				session.append(pssh(i,args.username, args.password,args.cmd,args.child))
			
			with concurrent.futures.ProcessPoolExecutor(max_workers=args.max_parallel) as executor:
				executor.map(run_cmd, session)
	
	if args.if_analysis != 'none':
		run_ifanalysis(args.if_analysis)
		

##Functions end here, start of main code#####
##

## main executes from here, we will verify all the packages have been correctly installed and imported correctly ##

if __name__ == '__main__':
	import time
	print('Checking system requirements....')
	time.sleep(1)
	try:
		import pexpect
		import getpass
		import argparse
		import sys, os
		from argparse import RawTextHelpFormatter
		import concurrent.futures
		from pkg_resources import parse_version
		from ciscoconfparse import CiscoConfParse
		
		if ((sys.hexversion < 50594288) or (parse_version(pexpect.__version__) < parse_version('4.0.*'))):
			print( 'Error:  Python version '+str(sys.version_info)+ ' or Pexpect version '+ pexpect.__version__+ ' does not meet minimum requirements, You must use Python 3.4.1+ and Pexpect 4.0+')
		else:
			main()
	except ImportError:
		print(' Error in importing the Module: ' 'Please make sure the required libraries (pexpect,getpass,argparse,ciscoconfparse, concurrent.futures) are correctly installed')
