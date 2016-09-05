PyIOS
=====
A Python script to do ssh to multiple Cisco Hosts and perform multiple operations with multiprocessing capablities, means you can do multiple tasks on multiple routers at same time.

This Script should run on Linux with SSH client installed.

It is using Python 3.4.1 code with Pexpect 4.0 library.

I have created this script for personal use and took the idea from different sources so you are free to use it, in case of any issue, report it.


Usage: PyIOS.py username [-h] [-m HOSTNAME] [-t] [-c CMD] [-a] [-p MAX_PARALLEL]


The Script runs in multiple modes:
It can run to implement/log the show/config sequential commands on the router.
It can run in Analyse mode where it needs to collect output of show commands/configurations from routers and apply logic to the data collected and generate desired output.


Positional arguments:

	Username		Define required Username to connect the hosts

Optional arguments:

	-h, --help		show this help message and exit
	
	-m HOSTNAME		Defines host manually, otherwise host names will be taken from hosts.txt in same folder.
					The formation of hosts in hosts.txt should be as following:
					host1
					host2
					host3

	-t				Specify -t for Telnet the hosts, otherwise by default its SSH.<Not Functional Yet>
                   
  
	-c CMD			Defines the command manually in "" (Double Quote), otherwise it will load multiple lines command
                    from cmd.cfg in same folder.
					The formation of commands in cmd.cfg should be as following:
					c1
					c2
					c3
                   
  
	-p MAX_PARALLEL By Default Script will open 10 processes parallel, it can be increased to desired value by using this switch.
