#!/usr/bin/python

import sys
import sqlite3
import socket
import ssl

default_request = """GET / HTTP/1.1
Host: %s
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:55.0) Gecko/20100101 Firefox/55.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1

"""

def fetch_page_hostname(ip,port,hostname,use_ssl=False):
  global default_request
  sock_default = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
  if use_ssl:
    sock = ssl.wrap_socket(sock_default)
  else:
    sock = sock_default
  sock.settimeout(1.0)
  try:
    sock.connect((ip,port))
  except socket.timeout:
    print "Timed out, skipping server %s on port %d" % (ip,port)
    return None
  except socket.error:
    print "General socket error, skipping %s on port %d" % (ip,port)
    return None
  sock.send(default_request % hostname)
  total_data = ""
  try:
    while True:
      data = sock.recv(4096)
      if not data:
        sock.close()
        break
      else:
        total_data += data
    sock.close()
  except:
    pass
  return total_data

# print fetch_page_hostname("216.58.200.100",443,"www.google.com",True)

def scan_vhosts(c):
  print "scan_vhosts called"
  c.execute("select * from resolved") 
  results = c.fetchall()
  hosts = []
  ips = []
  for (host,ip) in results:
    hosts.append(host)
    ips.append(ip)
  for ip in ips:
    for host in hostnames:
      d = test_single_name(ip,host)
      if len(d) < 10:
        print "VHost scan against %s returns nothing. Skipping..." % ip
        break

print "Module 'web' loaded" 
