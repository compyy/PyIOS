PySSh
=====

Simple SSH script to login to multiple Cisco Hosts and apply multiple commands.

This Script requires to run Linux with SSH client installed.

It is using Python 2.7.8 code with Pexpect library.

I have created this script for personal use and took the idea from different sources so you are free to use it, in case of any issue, report it.

This Script will ask for host manually, if Enter is pressed without entering any value it will take hosts from hosts.txt in same directory.

Username/Password should be provided.(for Security reasons)

Script will load cmd list from cmd.txt in same directory.

By Default Script will open 10 processes in parellel, it can be increased but 10 is good.
