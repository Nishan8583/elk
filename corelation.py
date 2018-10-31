#!/usr/bin/python
from elasticsearch import Elasticsearch
from elasticsearch import helpers
import json,time
from slackclient import SlackClient

def corelation(c):
	c.h1("\n\nCORELATION\n\n")
	s = SlackClient("xoxb-325104983714-KArhOLsscyh4cqOcvWBY9Ezw")
	es = Elasticsearch("127.0.0.1:9200")
	body = {
               "query": {
                  "bool": {
                     "must": [
                       { "match_all": { } }
                     ],
                  }
                }
              }
#result = es.search(index="rigo-2017.12.31",size=1000,body = body)
	results = helpers.scan(es,query=body,index='malicious_website')
	malicious_website_ip = []
	talos_ip = []
	ids_ip = []
	def searcher_virus():
	        for result in results:
				if result["_source"]["dest_ip"] not in malicious_website_ip:
					malicious_website_ip.append(result["_source"]["dest_ip"])

	searcher_virus()
	results = helpers.scan(es,query=body,index='threat-intel')
	def searcher_talos():
	        for result in results:
	                        if result["_source"]["destination_ip"] not in talos_ip:
	                                talos_ip.append(result["_source"]["destination_ip"])
	searcher_talos()

	body = {
               "query": {
                  "bool": {
                     "must": [
                       { "match": { "event_type" : "alert" } },
                        ],
                  }
                }
              }
	results = helpers.scan(es,query=body,index='suricata-index')
	def searcher_ids():
	        for result in results:
	                        if result["_source"]["dest_ip"] not in ids_ip:
	                                ids_ip.append(result["_source"]["dest_ip"])

	searcher_ids()
	message = 'CORELATION/CRITICAL THE FOLLOWING IP NEEDS TO BE BLOCKED ASAP\n'
    s.api_call("chat.postMessage",channel='project',text=message)
	for ip1 in talos_ip:
		for ip2 in malicious_website_ip:
			if ip1 == ip2:
				msg = "CORRELATION FOUND in the IP between virutotal domain info and talos malicious ip information: {}".format(ip1)
				print msg
				message = '\n\n'+ msg + "\n\n"
				s.api_call("chat.postMessage",channel='project',text=msg)

	for ip1 in malicious_website_ip:
	        for ip2 in ids_ip:
	                if ip1 == ip2:
	                        msg = "CORRELATION FOUND in the IP from IDS and malicious domain information from virustotal: {}".format(ip1)
	                        print msg
                                message = '\n\n'+ msg + "\n\n"
	                        s.api_call("chat.postMessage",channel='project',text=msg)
	for ip1 in talos_ip:
	        for ip2 in ids_ip:
	                if ip1 == ip2:
	                        msg = "CORRELATION FOUND in the IP from ids and talos: {}".format(ip1)
	                        print msg
                                message = '\n\n'+ msg + "\n\n"
	                        s.api_call("chat.postMessage",channel='project',text=msg)

	c.p(message)
