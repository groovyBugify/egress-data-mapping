#! Author: Saransh Rana;
#! /usr/bin/python3

import boto3
import json
import requests
import time
import re
from urllib import request, parse
import socket
from dns import resolver,reversename
import csv
import os.path

def get_all_nat():
    client = boto3.client('ec2',region_name='us-east-1')
    response = client.describe_nat_gateways()
    nat_id = list(map(lambda x:x['NatGatewayAddresses'][0]['NetworkInterfaceId'],response['NatGateways']))
    return nat_id

def enumerate_es_eni(eni):
    print(f"[+]Enumerating ENI: {eni}")
    try:
        headers = {"Content-Type": "application/json"}
        data = { 
            "query": {
                "bool":{
                    "must":{
                        "term": {
                            "interface_id": {
                                "value": eni
                            }
                        }
                    },
                    "must_not": {
                        "range":{
                            "dstaddr":{
                                "gte": "10.0.0.0",
                                "lte": "10.255.255.255"
                            }
                        }
                    }
                }
            }, 
            "aggs": {    
                "dstaddr":{      
                    "terms":{
                        "field":"dstaddr",
                        "size":10000
                    } 
                }    
            }
        }
        url = "http://vpcflowlog_cluster_endpoint/_search"
        r1 = requests.post(url=url, headers=headers, data=json.dumps(data), verify=False, timeout=None)
        print("making web request to es")
        if r1.status_code == 200:
            data = json.loads(r1.text)
            data_len = data['aggregations']['dstaddr']['buckets']
            print(f'[+]Length of buckets rxd from VPC Flow logs: {len(data_len)}')
            if len(data_len) > 0:
                for ips in data_len:
                    ip = ips['key']
                    count = ips['doc_count']         
                    #print(ip, count)
                    send_answer(eni, ip, count)
            else:
                print(f'[+]Length of bucket equal to 0, hence passing this {eni}')
        else:
            print(f'error: {r1.text}')
    except Exception as em:
        print(f"[+]got exception at enumerate_es_eni: {em}")
        pass

def cloudfront_es(ip):
    #print(f"[+]IP Recieved at CF ES: {ip}")
    try:
        url = "https://cloudfront_elk_cluster/_search"
        headers = {"Content-Type": "application/json"}
        data = {
                "query": {
                        "bool": {
                            "must":{
                                "wildcard":{
                                    "c_ip": {
                                        "value": f"{ip}"
                                    }
                            }
                        }
                    }
                },
                "aggs": {    
                        "cs_uri_stem":{      
                                "terms":{
                                    "field":"cs_uri_stem.keyword",
                                    "size":10
                        } 
                    }    
                }
            }
        r1 = requests.post(url=url, headers=headers, data=json.dumps(data), timeout=None)
        if r1.status_code == 200:
            data = json.loads(r1.text)
            data_len = data['aggregations']['cs_uri_stem']['buckets']
            if len(data_len) == 0:
                return None, None
            else:
                for key in data_len:
                    return key['key'], key['doc_count']                
    except Exception as em:
        print(f'[+]Exception at cloudfront_es: {em}')
        
def send_answer(eni, ip, count):
    key, doc_count = cloudfront_es(ip)
    if doc_count != None and key != None:
        print(f'The {ip} has made calls to the following endpoints {key}, {doc_count} times')
        geoip = get_geoip_details(ip)
        location = geo_ip_processor(geoip)
        reverse_dns = reverse_lookup(ip)
        print()
        print(f"[+]The IP {ip} was invoked from {location}")
        write_csv(eni, ip, count, location,reverse_dns, key)
    else:
        geoip = get_geoip_details(ip)
        location = geo_ip_processor(geoip)
        reverse_dns = reverse_lookup(ip)
        print(f"[+]The IP {ip} was invoked from {location}")
        write_csv(eni, ip, count, location, reverse_dns)

# Write to all skipped packages to CSV 
def write_csv(eni, ip, count, location, revDns, paths=None):
    empty_list = []
    if paths == None:
        result = {'NAT Gateway': eni, 'IP': ip, 'Count': count, 'Location': location, 'Reverse DNS Lookup': revDns,'Common Paths from CloudFront ES': ''}
        empty_list.append(result)
    else:
        result = {'NAT Gateway': eni, 'IP': ip, 'Count': count, 'Location': location, 'Reverse DNS Lookup': revDns, 'Common Paths from CloudFront ES': paths}
        empty_list.append(result)

    filename = 'egress-data-infra.csv'
    file_exists = os.path.isfile(filename)
    headers = ['NAT Gateway', 'IP', 'Count', 'Location', 'Reverse DNS Lookup', 'Common Paths from CloudFront ES']
    
    with open(f'./{filename}', 'a') as f:
        writer = csv.DictWriter(f, fieldnames=headers)
        if not file_exists:
            writer.writeheader()
        writer.writerows(empty_list)
    

# Reverse DNS Lookup 
def reverse_lookup(ip):
    addr=reversename.from_address(ip)
    try:
        answer = resolver.resolve(addr, 'PTR')
        return str(answer[0])
    except Exception as em:
        return None
        pass

# IP Enrichment
def get_geoip_details(userIP):
    ip = userIP
    try:
        socket.inet_aton(ip)
    except socket.error:
        return 'null'
    if ip.startswith('172.') or ip.startswith('192.168.') or ip.startswith('10.'):
        return 'null'
    enrichment_service = 'https://ipinfo.io/' + str(ip)
    try:
        req = request.Request(enrichment_service, headers={'Content-Type': 'application/json'})
        response = request.urlopen(req)
        s = response.read().decode('utf-8')
        if '{' not in s:
            return 'null'
        else:
            geoip = json.loads(s)
            return geoip
    except Exception as em:
            print('[+]EXCEPTION at GEOIP Func: {}'.format(str(em)))

# Geo IP Result Processor
def geo_ip_processor(geoip):
    if 'null' in geoip:
        location = 'N/A'
        return location            
    elif 'exception' in geoip:
        location = 'Exception occured'
        return location
    else:
        if geoip['org'] != '':
            location = geoip['city'] + ', ' + geoip['country'] + ' | ' + geoip['org']
            return location
        else:
            location = geoip['city'] + ', ' + geoip['country']
            return location

if __name__ == "__main__":
    nat_eni = get_all_nat()
    for n in nat_eni:
        enumerate_es_eni(n)
