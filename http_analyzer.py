#!/usr/bin/python
from brothon import bro_log_reader
from file import scan
import time
import json
from elasticsearch import Elasticsearch
from  datetime import datetime

def http_analyzer(c):
	msg = ''
	c.h1("\n\nHTTP_HUNT")
        es = Elasticsearch("localhost:9200")
        reader = bro_log_reader.BroLogReader("http.log")  # This object reads from the log from the mentioned location
        n = datetime.now()
        # THe below line has been commented, if info about the key and value pairs is requierd can be uncommented to see them
        url_list = []  # just a sample malicious site
        i = 0
        my_dict = {}  # will hold the json value

        for row_dict in reader.readrows():
                print "\n\n"
                print "\n\n"
                try:
                        row_dict['host']  # Sometimes this key may not be present
                        if row_dict['host'] == '-':
                                continue
                        pass  # If key is present go ot the next script
                except:
                        continue  # If key is not present go to top of loop

                if row_dict['host'] not in url_list:  # Getting only the URLs
                        url_list.append(row_dict['host'])
                        if i == 0:
                                pass
                        elif i % 4 == 0:  # Becasue the limitation of VIrustotal PUblci API is 4 scans per minute
                                print "[*]NEED A TIMEOUT \n"
                                time.sleep(60)
                        try:
                                r = scan(row_dict['host'])
                        except:
                                continue
                        if r and r[1] > 0:  # if malicious
                                print r
                                print "a malicious site"
                                my_dict["src_ip"] = row_dict["id.orig_h"]
                                my_dict["src_port"] = row_dict["id.orig_p"]
                                my_dict["dest_ip"] = row_dict["id.resp_h"]
                                my_dict["dest_port"] = row_dict["id.resp_p"]
                                my_dict["refferer"] = row_dict["referrer"]
                                my_dict["method"] = row_dict["method"]
                                my_dict["link"] = row_dict['host']
                                my_dict["type"] = "HTTP"
                                my_dict["@timestamp"] = datetime.now().isoformat()
                                my_dict["ip_void"] = "http://www.ipvoid.com/scan/{}".format(row_dict["id.resp_h"])
                                my_dict["sender_base"] = "http://www.senderbase.org/lookup/?search_string={}".format(row_dict["id.resp_h"])
                                my_dict["virustotal"] = "https://www.virustotal.com/en/ip-address/{}/information/".format(row_dict["id.resp_h"])
                                my_dict["threat-intel-source"] = "Virustotal"
				msg = msg + "Source_ip: {}\nDestination_ip: {}\nSource_port: {}\nDestination_port: {}\nDomain:{}\n".format(my_dict["src_ip"],my_dict["dest_ip"],my_dict["src_port"],my_dict["dest_port"],my_dict["link"])
                                body = json.dumps(my_dict)
                                try:
                                        es.create(index = "malicious_website",doc_type="practise",body = body)
                                        print "sucess"
                                except:
                                        es.index(index = "malicious_website",doc_type="practise",body = body)
                                        print "wut"
                                my_dict = {}
                        else:
                                pass
                i = i + 1
		c.p(msg)

