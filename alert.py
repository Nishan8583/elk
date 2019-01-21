#!/usr/bin/python
from elasticsearch import Elasticsearch
from elasticsearch import helpers
import json,time
from datetime import datetime
from slackclient import SlackClient

__authors__ = "Nishan Maharjan"
s = SlackClient("api key here")

def alerts(results,L,c):
        msg = "SURICATA-LOGS\n"
        for result in results:
		print result
                if result not in L:
                        L.append(result)
                        print "888888888888\n\n"
                        msg = msg + "\n\n-------------------------------------------------------------------------------------------\n\nALERT_FROM_IDS\n"
                        msg = msg + "src_ip= "+result["_source"]["src_ip"] + "            "
                        msg = msg + "dest_ip= " + result["_source"]["dest_ip"] + "                "
                        msg = msg + "ALERTS= " + result["_source"]["alert"]["signature"] + "            "
                        my_date = (str(result["_source"]["timestamp"])).replace(":"," ")
                        #my_date = "YEAR= "+ str(my_date.year) + "   MONTH= " + str(my_date.month) + "  DAY=" + str(my_date.day) + "            HOUR=" + str(my_date.hour)
                        msg = msg + "DATE= " +str(my_date)  + "         "
                        msg = msg + "\n\n-------------------------------------------------------------------------------------------\n\n"
                else:
                        pass
        print msg
	msg = msg + "\n\n"
	c.h1("\n\nIDS_ALERTS")
	c.p(msg)
        s.api_call("chat.postMessage",channel='project',text=msg)
        return L




def searcher(L,c):

        es = Elasticsearch("localhost:9200")
        body = {
               "query": {
                  "bool": {
                     "must": [
                       { "match": { "event_type" : "alert" } },
                        ],
                  }
                }
              }


        result1 = helpers.scan(es,query=body,index="suricata-index")  # Quering elasticsearch, returns generator object
        L = alerts(result1,L,c)
        return L

