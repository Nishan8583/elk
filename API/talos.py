import requests, re, time
from lxml import html
class TalosIP(object):
  def __parse_results(self, json_result):
        result = {'email_volume':{}, 'volume_change':{}}
        #del json_result['category']
        try:
          if json_result.get('dnsmatch') == 1:
            result['fwd_rev_dns_match'] = "True"
          elif json_result.get('dnsmatch') == 0:
            result['fwd_rev_dns_match'] = "False"
        except:
          result['fwd_rev_dns_match'] = "NA"
          pass
        result['ip'] = json_result.get('ip')
        result['email_reputation'] = str(json_result.get('email_score_name'))
        result['web_reputation'] = str(json_result.get('web_score_name'))
        try:
                result['web_category'] = str(json_result.get('category')['description'])
        except:
                pass
        result['email_volume']['last_day'] = str(json_result.get('daily_mag'))
        result['email_volume']['last_month'] = str(json_result.get('monthly_mag'))
        result['volume_change']['last_day'] = str(json_result.get('daychange'))
        result['volume_change']['last_month'] = str(json_result.get('monthchange'))
        result['host_name'] = str(json_result.get('hostname'))
        result['domain'] = str(json_result.get('domain'))
        result['network_owner'] = str(json_result.get('organization'))
        #Testing for Blacklists
        try:
                if json_result["blacklists"]["cbl.abuseat.org"]["rules"] == [[u'Cbl', u'Spam source']]:
                        result['blacklist'] = "True"
                elif json_result["blacklists"]["pbl.spamhaus.org"]["rules"] == [[u'Pbl', u'Spam source']]:
                        result['blacklist'] = "True"
                elif json_result["blacklists"]["sbl.spamhaus.org"]["rules"] == [[u'Sbl', u'Spam source']]:
                        result['blacklist'] = "True"
                elif json_result["blacklists"]["bl.spamcop.net"]["rules"] == [[u'Bl', u'Spam source']]:
                        result['blacklist'] = "True"
                else:
                        result['blacklist'] = "False"
        except:
                result['blacklist'] = "NA"
        print result
        return result


  def lookup_ip(self, search_string):
      try:
          req = 'https://talosintelligence.com/sb_api/query_lookup?query=%2Fapi%2Fv2%2Fdetails%2Fip%2F&query_entry='
          json_result = requests.get('%(req)s%(search_string)s' % {'req':req, 'search_string':search_string}, timeout=30,
headers={'referer':'https://talosintelligence.com/'}).json()
          return self.__parse_results(json_result)
      except:
          return {'talos_resp' : 'could not fetch data from talos'}
  def lookup_domain(self, search_string):
    try:
        req = 'https://talosintelligence.com/sb_api/query_lookup?query=%2Fapi%2Fv2%2Fdetails%2Fdomain%2F&query_entry='
        json_result = requests.get('%(req)s%(search_string)s' % {'req':req, 'search_string':search_string}, timeout=30,
headers={'referer':'https://talostintelligence.com'}).json()
        return self.__parse_results(json_result)
    except:
        return {"talos_resp":"could not fetch data from talos"}

