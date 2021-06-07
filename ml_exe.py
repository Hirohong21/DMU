# Regex
import re
# Request URL
import requests
import urllib
# Parse URLs
from urllib.parse import urlparse
# IP whois lookup
from ipwhois import IPWhois

import sys
import socket

# Managing Datasets
import pandas as pd
import numpy as np
import math

import ml_input as ml_models

url = sys.argv[1]
url_df = pd.DataFrame(data={'url':url}, index=[0])

#Depending on the URL type, different methods will be applied e.g. if a URL is an IP address
def url_type(row):
    # If domain contains a letter\n",
    # The domain is usally an IP followed by port or URL\n",
    if re.search("[a-z,A-Z]", urlparse(row['url']).netloc.replace('www.', '')):
        return 1
    else:
        return 0

url_df['url_type'] = url_df.apply(lambda row: url_type(row), axis=1)

def parse_url():
    for index, row in url_df.iterrows():
        parse = urlparse(row['url'])
        url_df.at[index, 'scheme'] = parse.scheme
        url_df.at[index, 'netloc'] = parse.netloc
        url_df.at[index, 'path'] = parse.path
        url_df.at[index, 'params'] = parse.params
        url_df.at[index, 'query'] = parse.query
        url_df.at[index, 'fragment'] = parse.fragment

parse_url()

def get_port(row):
    if row['url_type'] == 0:
        try:
            return int(urlparse(row['url']).netloc.split(':')[1])
        except:
            pass
    if row['url'].startswith('https'):
        return 443
    elif row['url'].startswith('http'):
        return 80
    elif row['url'].startswith('ftp'):
        return 21
    else:
        return 0
    
url_df['port'] = url_df.apply(lambda row: get_port(row), axis=1)

def get_ip():
    for index, row in url_df.iterrows():
        ip = None
        if row['url_type'] == 0:
            ip = urlparse(row['url']).netloc.replace('www.', '').split(':')[0]
        else:
            try:
                ip = socket.gethostbyaddr(row['netloc'])
            except:
                pass
        if type(ip) is tuple:
            ip = ip[2][0]
        if ip:
            ip_parts = ip.split('.')
            url_df.at[index, 'ip_1'] = int(ip_parts[0])
            url_df.at[index, 'ip_2'] = int(ip_parts[1])
            url_df.at[index, 'ip_3'] = int(ip_parts[2])
            url_df.at[index, 'ip_4'] = int(ip_parts[3])
            url_df.at[index, 'ip'] = ip
        
get_ip()

# Get hostname for IP URLs
def get_url():
    for index, row in url_df.iterrows():
        if row['url_type'] == 0:
            try:
                url = socket.gethostbyaddr(row['ip'])
                
                scheme = row['scheme'] or ''
                path = row['path'] or ''
                params = row['params'] or ''
                query = row['query'] or ''
                fragment = row['fragment'] or ''
                
                url_df.at[index, 'url'] = f'{scheme}://{url[0]}{path}{params}{query}{fragment}'
            except:
                pass

get_url()


def special_char_count(row, char):
    return row['url'].count(char)

special_chars = ['[', ']', '{', '}', '(', ')', ';', ':', '\'', '@', '#', '~', '<', '>', ',', '.', '?', '/', '\\', 
                 '|', '`', '¬', '!', '"', '^', '&', '*', '-', '_', '+', '=', '%', '$', '£']

for char in special_chars:
    url_df[f'contains {char}'] = url_df.apply(lambda row: special_char_count(row, char), axis=1)

def url_length(row):
    return len(row['url'])

url_df['url length'] = url_df.apply(lambda row: url_length(row), axis=1)

def contains_https(row):
    if row['url'].startswith('https'):
        return 1
    return 0

url_df['https'] = url_df.apply(lambda row: contains_https(row), axis=1)

def top_level_domain(row):
    if row['url_type'] == 1:
        return row['netloc'].split('.')[-1]
    ip = urlparse(row['url']).netloc.split(':')[0]
    try:
        domain = urllib.request.urlopen(ip)
        return urlparse(domain.url).netloc.split('.')[-1:][0]
    except:
        return 0

url_df['top_level_domain'] = url_df.apply(lambda row: top_level_domain(row), axis=1)

def netloc_length(row):
    return len(row['netloc'])

def path_length(row):
    return len(row['path'])

def params_length(row):
    return len(row['params'])

def query_length(row):
    return len(row['query'])

def fragment_length(row):
    return len(row['fragment'])

url_df['netloc_length'] = url_df.apply(lambda row: netloc_length(row), axis=1)
url_df['path_length'] = url_df.apply(lambda row: path_length(row), axis=1)
url_df['params_length'] = url_df.apply(lambda row: params_length(row), axis=1)
url_df['query_length'] = url_df.apply(lambda row: query_length(row), axis=1)
url_df['fragment_length'] = url_df.apply(lambda row: fragment_length(row), axis=1)


def who_is():
    for index, row in url_df.iterrows():
        if row['ip'] == '' or row['ip'] is None:
            continue
        try:
            whois = IPWhois(row['ip'])
            lookup = whois.lookup_whois()
            nets = lookup.get('nets')[0]
            url_df.at[index, 'asn_reg'] = lookup.get('asn_registry', '0')
            url_df.at[index, 'asn'] = lookup.get('asn', '0')
            url_df.at[index, 'asn_country_code'] = lookup.get('asn_country_code', '0')
            url_df.at[index, 'asn_date'] = lookup.get('asn_date', '0')
            url_df.at[index, 'nets_country_code'] = nets.get('country', '0')
        except:
            pass

who_is()


def request_info():
    for index, row in url_df.iterrows():
        try:
            r = requests.get(row['url'], timeout = 5)
            headers = r.headers
            url_df.at[index, 'status_code'] = int(r.status_code)
            url_df.at[index, 'is_redirect'] = r.is_redirect
            url_df.at[index, 'server'] = headers.get('server', '0')
            url_df.at[index, 'expires'] = headers.get('expires', '0')
            url_df.at[index, 'content_length'] = headers.get('content-length', '0')
            url_df.at[index, 'content_type'] = headers.get('content-type', '0')
            url_df.at[index, 'x_powered_by'] = headers.get('x-powered-by', '0')
            url_df.at[index, 'strict_transport_security'] = headers.get('strict-transport-security').get('max-age', '0')
            url_df.at[index, 'transfer_encoding'] = headers.get('transfer-encoding', '0')
            r.close()
        except:
            pass

request_info()

def get_month_num(month):
    if month == 'Jan':
        return 1
    elif month == 'Feb':
        return 2
    elif month == 'Mar':
        return 3
    elif month == 'Apr':
        return 4
    elif month == 'May':
        return 5
    elif month == 'Jun':
        return 6
    elif month == 'Jul':
        return 7
    elif month == 'Aug':
        return 8
    elif month == 'Sep':
        return 9
    elif month == 'Oct':
        return 10
    elif month == 'Nov':
        return 11
    elif month == 'Dec':
        return 12
    else:
        return 0
    

# Create one hot encoding values and columns
tlds = pd.get_dummies(url_df["top_level_domain"],prefix='tld',  dummy_na=True)
url_df = url_df.join(tlds)

servers = pd.get_dummies(url_df["server"],prefix='servers',  dummy_na=True)
url_df = url_df.join(servers)

asn_country_codes = pd.get_dummies(url_df["asn_country_code"],prefix='asn_country_code',  dummy_na=True)
url_df = url_df.join(asn_country_codes)

nets_country_codes = pd.get_dummies(url_df["nets_country_code"],prefix='nets_country_code',  dummy_na=True)
url_df = url_df.join(nets_country_codes)

status_codes = pd.get_dummies(url_df["status_code"],prefix='status_code',  dummy_na=True)
url_df = url_df.join(status_codes)

asn_regs = pd.get_dummies(url_df["asn_reg"],prefix='asn_reg',  dummy_na=True)
url_df = url_df.join(asn_regs)

x_powered_by = pd.get_dummies(url_df["x_powered_by"],prefix='x_powered_by',  dummy_na=True)
url_df = url_df.join(x_powered_by)

for index, row in url_df.iterrows():
    if 'GMT' in str(row['expires']):
        expires = row['expires'].split(' ')
        url_df.at[index, 'expires_year'] = int(expires[3])
        url_df.at[index, 'expires_month'] = int(get_month_num(expires[2]))
        url_df.at[index, 'expires_day'] = int(expires[1])
    else:
        if isinstance(row['expires'], int):
            url_df.at[index, 'expires_year'] = row['expires']
            url_df.at[index, 'expires_month'] = row['expires']
            url_df.at[index, 'expires_day'] = row['expires']
        else:
            url_df.at[index, 'expires_year'] = 0
            url_df.at[index, 'expires_month'] = 0
            url_df.at[index, 'expires_day'] = 0
    
    
for index, row in url_df.iterrows():
    if '-' in str(row['asn_date']):
        asn_date = row['asn_date'].split('-')
        url_df.at[index, 'asn_date_year'] = int(asn_date[0])
        url_df.at[index, 'asn_date_month'] = int((asn_date[1]))
        url_df.at[index, 'asn_date_day'] = int(asn_date[2])
    else:
        if isinstance(row['asn_date'], int):
            url_df.at[index, 'asn_date_year'] = row['asn_date']
            url_df.at[index, 'asn_date_month'] = row['asn_date']
            url_df.at[index, 'asn_date_day'] = row['asn_date']
        else:
            url_df.at[index, 'asn_date_year'] = 0
            url_df.at[index, 'asn_date_month'] = 0
            url_df.at[index, 'asn_date_day'] = 0
    
url_df = url_df.drop('asn_date', axis=1).drop('expires', axis=1)
    

url_df = pd.DataFrame(url_df).fillna('-1')


url_df = url_df.drop("url", axis=1).drop("url_type", axis=1).drop("scheme", axis=1)
url_df = url_df.drop("netloc", axis=1).drop("path", axis=1).drop("params", axis=1).drop("query", axis=1)
url_df = url_df.drop("fragment", axis=1).drop("ip", axis=1).drop("top_level_domain", axis=1).drop("asn_reg", axis=1)
url_df = url_df.drop("asn_country_code", axis=1).drop("nets_country_code", axis=1).drop("is_redirect", axis=1)
url_df = url_df.drop("server", axis=1).drop("content_type", axis=1).drop("x_powered_by", axis=1).drop("asn", axis=1)

results = ml_models.execute(url_df)
print(results)







