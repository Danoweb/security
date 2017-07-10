#!/usr/bin/python

import win32con
import win32api
import win32security

import wmi
import sys
import os

def log_to_file( message ):
	fd = open("process_monitor_log.csv", "a+")
	fd.write(message + "\r\n")
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

