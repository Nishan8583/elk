#!/usr/bin/python
from elasticsearch import Elasticsearch
from elasticsearch import helpers
from talos import TalosIP
import json
from brothon import bro_log_reader
from datetime import datetime
obj = TalosIP()

__author__ = "Nishan Maharjan"
def searcher():
	es = Elasticsearch("127.0.0.1:9200")
	reader = bro_log_reader.BroLogReader("http.log")
	l = []

        for row_dict in reader.readrows():  # The result is list of json objects
                print "\n"
                try:
                        ip = row_dict["id.resp_h"]  # Getting the source IP field, it is inside a try statement cause not every query hits will have this field
                except:
                        continue
                if ip not in l:  # Query only if the IP has not been queried yet
                        l.append(ip)  # Appending it in the list
                        nyasro = obj.lookup_ip(ip)  # Talos lookup
                        if "not fetch" not in str(nyasro):  # If the talos lookup did not failed
				 if nyasro["web_reputation"] == "Poor" or nyasro["email_reputation"] == "Poor":
                                        nyasro["@timestamp"] = datetime.now().isoformat()
                                        nyasro["destination_ip"] = row_dict["id.resp_h"]
                                        nyasro["source_ip"] = row_dict["id.orig_h"]
                                        nyasro["source_port"] = row_dict["id.orig_p"]
                                        nyasro["destination_port"] = row_dict["id.resp_p"]
                                        print nyasro

					try:
                                		es.create(index = "threat-intel",doc_type="threat",body = nyasro)
                                		print "sucess"
                        		except:
                                		es.index(index = "threat-intel",doc_type="threat",body = nyasro) 

searcher()
