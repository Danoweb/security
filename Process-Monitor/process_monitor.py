#!/usr/bin/python

import win32con
import win32api
import win32security

import wmi
import sys
import os

def log_to_file( message ):
	fd = open("process_monitor_log.csv", "a+")
	fd.write(message + "\n")
	fd.close()
	return

def get_process_privileges(pid):
	try:
		#OBTAIN A HANDLE TO THE TARGET
		hproc = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION,False,pid)
		
		#OPRN THE MAIN PROCESS TOKEN
		htok = win32security.OpenProcessToken(hproc,win32con.TOKEN_QUERY)
		
		#RETRIEVE THE LIST OF PRIVLEGES ENABLED
		privs = win32security.GetTokenInformation(htok,win32security.TokenPrivileges)
		
		#ITERATE OVER PRIVELEGES AND OUTPUT THE ENABLED
		priv_list = ""
		for i in privs:
			#CHECK IF PRIVILEGE IS ENABLED
			if i[1] == 3:
				priv_list += "%s|" % win32security.LookupPrivilegeName(None,i[0])
	
	except:
		priv_list = "N/A"
	return priv_list
	
#CREATE A LOG FILE HEADER
header = "Time,User,Executable,CommandLine,PID,Parent PID,Privileges"
log_to_file(header)

#INSTANTIATE THE WMI INTERFACE
c = wmi.WMI()

#CREATE OUR PROCESS MONITOR
process_watcher = c.Win32_Process.watch_for("creation")

while True:
	try:
		new_process = process_watcher()
		proc_owner = new_process.GetOwner()
		proc_owner = "%s\\%s" % (proc_owner[0],proc_owner[2])
		create_date = new_process.CreationDate
		executable = new_process.ExecutablePath
		cmdline = new_process.CommandLine
		pid = new_process.ProcessId
		parent_pid = new_process.ParentProcessId
		privileges = get_process_privileges(pid)
		process_log_message = "%s,%s,%s,%s,%s,%s,%s" % (create_date,proc_owner,executable,cmdline,pid,parent_pid,privileges)
		
		print (process_log_message)
		
		log_to_file(process_log_message)
	#EXIT OUT ON KEYBOARD CTRL-C
	except KeyboardInterrupt:
		print ("Keyboard Exit Command - Exiting...")
		sys.exit()
	#CATCH ALL OTHER ERRORS
	except:
		#PRINT ERRORS
		#pass
		
		e = sys.exc_info()
		print(e)
