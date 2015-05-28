#! /usr/bin/python

"""
Check readme for Help

"""

from multiprocessing import Pool
import pexpect
import getpass
import time

# Start of code

host = raw_input("Press Just Enter if you want to collect hosts from host.txt or Enter hostname/IP Manually: ")
user = raw_input("Enter Username: ")
passwd = getpass.getpass("Enter Password: ")

##Definging Execution Function##############

def cexecute(host):
    ssh_newkey = 'Are you sure you want to continue connecting (yes/no)?'
    constr = 'ssh ' + user + '@' + host
    ssh = pexpect.spawn(constr)
    ret = ssh.expect([pexpect.EOF, ssh_newkey, '[P|p]assword:'],timeout=120))

    if ret == 0:
        print ('[-] Error Connecting to ' + host +' May be host is not resolvable or not responding')
        return 0

    if ret == 1:
        ssh.sendline('yes')
        ret = ssh.expect([pexpect.TIMEOUT, '[P|p]assword:'])
        
        if ret == 0:
            print ('[-] Could not accept new key from ' + host)
            return 0

    ssh.sendline(passwd)
    auth = ssh.expect(['[P|p]assword:', '>', '#'])

    if auth == 0:
        print (host + ' User password is incorrect')
        return 0
        
    if auth == 1:
        #print('username and password are correct')
        ssh.sendline('enable')
        ssh.expect('[pP]assword:')
        ssh.sendline(passwd)
        enable = ssh.expect(['[P|p]assword:', '#'])
        
        if enable == 0:
            print (host + ' enable password is incorrect')
            return 0
        
        if enable == 1:
            cmd = open("cmd.cfg", "r")
            logf = open("logs/" +host, "w")
            
            ssh.sendline('terminal length 0')
            for i in cmd:
                ssh.sendline(i.strip())
                ssh.expect('#',timeout=180)
                logf.write(ssh.before)
                logf.write("\n")
                #print(ssh.before)
                time.sleep(1)
            print ("CMD executed, on " + host +" script is exiting...")
            ssh.close()
            

##Function ends here#####

if host != "":
    cexecute(host)

else:
    hosts = [line.strip() for line in open("hosts.txt", 'r')]
    #pool = Pool(len(hosts))
    pool = Pool(10)
    pool.map(cexecute, hosts, 1)
    pool.close()
    pool.join()
