#!/usr/bin/python
from brothon import bro_log_reader
from file import scan
import time
from slackclient import SlackClient

def scan_files(c):
	s = SlackClient("api key here")
	c.h1("\n\nMaliciou Files Downloaded")
	message = ""
	malicious_files_downloaded = []
	filename = ''
	reader = bro_log_reader.BroLogReader("download.log")  # Reading from this log file


	for row in reader.readrows():  # Reading each row from the bro logs
		try:
			if row['method'] == 'GET':
				filename = row['host'] + row['uri']
				print filename
				if filename not in malicious_files_downloaded:
					malicious_files_downloaded.append(filename)
		                        try:
                                		r = scan(filename)
                        		except:
                                		continue
                        		if r and r[1] > 0:  # if malicious
		                                message = message + "A mal file was downloaded {}\n".format(filename)
						break

		except:
			pass
	print "\n\nWriting to pdf"
	c.p(message)
	s.api_call("chat.postMessage",channel='project',text=message)



