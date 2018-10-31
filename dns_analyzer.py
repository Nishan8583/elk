#!/usr/bin/python
from brothon import bro_log_reader
from file import scan
from elasticsearch import Elasticsearch
import time
import json

reader = bro_log_reader.BroLogReader("dns.log")
dns_replier_list = []
dns_requested_url = []

my_dict = {}

def put_in_string(message,my_dict):
        message = message + "\n\nSource_IP: {}\nSource_port: {}\nDestination_ip: {}\nDestination_port: {}\nQuery: {}\n".format(my_dict["src_ip"],my_dict["src_port"],my_dict["dest_ip"],my_dict["dest_port"],my_dict["query"])
        return message
def search_dns(c):
        i = 0
        dns_replier_list = []
        dns_requested_url = []

        my_dict = {}

        message = ""
        es = Elasticsearch("localhost:9200")
        for row in reader.readrows():
                print row['query']
                if row['query'] not in dns_requested_url:
                        dns_requested_url.append(row['query'])
                        if i == 0:
                                pass
                        elif i % 4 == 0:  # Becasue the limitation of VIrustotal PUblci API is 4 scans per minute
                                print "[*]NEED A TIMEOUT \n"
                                time.sleep(60)
                        r = scan(str(row['query']))
                        print r
                        print r[1]
                        if r and r[1] > 0:  # if malicious
                                print "a malicious query"
                                my_dict["src_ip"] = row["id.orig_h"]
                                my_dict["src_port"] = row["id.orig_p"]
                                my_dict["dest_ip"] = row["id.resp_h"]
                                my_dict["dest_port"] = row["id.resp_p"]
                                my_dict["query"] = row['query']
                                my_dict["type"] = "QUERY"
                                body = json.dumps(my_dict)
                                message = message + put_in_string(message,my_dict)
                                try:
                                        es.create(index = "malicious_website",doc_type="practise",body = body)
                                        print "sucess"
                                except:
                                        es.index(index = "malicious_website",doc_type="practise",body = body)
                                        print "wut"
                                my_dict = {}
                                break

                        i = i + 1
                        my_dict = {}
        print message
        c.h1("DNS HUNT\n\n")
        c.p(message)

