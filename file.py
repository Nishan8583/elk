#!/usr/bin/python
from VirusTotal import PublicApi  # publicapi was downlaoded from https://github.com/blacktop/virustotal-api/blob/master/virus_total_apis/api.py
'''THe function below (convert()) converts a unicode dictionary into normal one
   NOT MY OWN SCRIPT AND WAS DOWNLOADED FROM another site
   convert() was downloaded from:
   https://stackoverflow.com/questions/1254454/fastest-way-to-convert-a-dicts-keys-values-from-unicode-to-str
'''


def scan(link):
	obj = PublicApi("ac5d922e95729b2f6b0390d43ac14a0b250fbb73995bb49ca37cf52569bdca1f")  # the virustotal API
	obj.scan_url(link)  # scanning the url through virustotal
	try:
		resp = obj.get_url_report(link)  # getting the report
		print "Successfully obtaind url:{}  info from virustotal".format(link)
	except:
		print "unexpected failure"
	r = resp
	try:
		s = r['results']  # results is a key, and rest of the value is in the key
		if s['positives'] > 0:
			return [link,s['permalink']]
	except:
		print "Probable Limitation of the API key or virustotal could not find the informaiton on the given link {}".format(link)
		pass
# The function below posts the data to the elastic search server
#post_data('http://where_elastic_search_with_port_numbers_also_location_to_url_object',permalink_dict)

