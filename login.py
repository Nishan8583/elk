#!/usr/bin/python
from elasticsearch import Elasticsearch
import sys
from elasticsearch import helpers
import json
from slackclient import SlackClient

def search_brute_force(c):
	s = SlackClient("api key here")

	try:
        	es = Elasticsearch('localhost:9200')  # trying to connect to the elastic server
        	print "[+] SUCCESSFULLY CONNECTED TO ELASTICSEARCH SERVER"
	except:
	        print "[-] ERROR, COULD NOT CONNECT TO THE ELASTICSEARCH SERVER, CHECK YOU NETWORK CONNECTION"
	        print "[-] NOW EXITING !!!!!!!!!!!!!!!"
	        sys.exit(-1)
	body1 = {
                "query":
                        {
                                "match_all": {}  # An elasticsearch query to match all
                        }

        }

	results = helpers.scan(es,query=body1,index='fun-2018.02.16')
	users = {}  # will add users here
	print "[*] Successfully sent the query and here is the result"
	prob = ['high','medium','normal']

	'''The function below scans for possible brute force attacks'''

        for i in results:  # JSON object, after these keys the real values we need start
		print i['_source']["event_id"]
                if i['_source']["event_id"] == 4625:  # 4625 for login failure
			print "One event"
			file = open("sample.json",'a')
			json.dump(i,file)
			file.close()
                        if i['_source']['log_name'] in users:  # get login username
				print "Count increasing {}".format(i['_source']['log_name'])
                                users[i['_source']['log_name']] = users[i['_source']['log_name']] + 1  # increase the cound
                        else:
				print "new user {}".format(i['_source']['log_name'])
                                users[i['_source']['log_name']] = 1  # add the cound
                print "_______________________________________________________"
                print"                  NEXT                            "
                print "______________________________________________________"


        for user in users:

                if users[user] > 20:  # Becuse the number of failured login for a single day should not be so high
                        print "[*] Possible brute force {}".format(user)
			msg = "[*] Possible brute force attempt by {}".format(user)
			c.h1("\n\nBRUTE_FORCE_RESULTS")
			msg = msg + "\n\n"
			c.p(msg)
			s.api_call("chat.postMessage",channel='project',text=msg)



#search_brute_force()
