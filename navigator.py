#!/usr/bin/env python

import sys
import dns.resolver
import tldextract
import logging
import sqlite3
import os
import Queue
import socket
import time
import re
import uuid
import importlib
import glob
import modules
import core.db
import core.blacklist
from threading import Thread, Lock
from tldextract.tldextract import LOG

WORDS_FILE = "words.txt"
DIFF_MODE = False
ZDNS_BACKEND = False
NAMESERVER_LIST = []
resolveFile = None

CNAME_PREFIX = "_cname_"
RESOLVE_PREFIX = "_resolve_"
SCAN_PREFIX = "_scan_"
THREADS_MAX = 5
logging.basicConfig(level = logging.CRITICAL)

alt_words = None
base_name = ""
settings = {}
q = Queue.Queue()

starttime = time.time()

threadHandler = []
def _threaded_resolve(l,miscdata,r,full_host):
  global lock
  try:
    dnsobj = r.query(full_host,"A")
    ip = dnsobj[0]
    if ip is not None:
      lock.acquire()
      l.append((full_host,ip))
      lock.release()
      print "%s,%s,%s" % (RESOLVE_PREFIX,full_host,ip)
      # return
  except dns.resolver.NXDOMAIN:
    pass
  except dns.resolver.NoNameservers:
    print "Info: dns.resolver.NoNameservers raised for A '%s'" % full_host
  # 'should' isn't 'must' when it comes to RFC's :)
  try:
    dnsobj = r.query(full_host,"CNAME")
    cname = dnsobj[0]
    if cname is not None:
      lock.acquire()
      miscdata.append((full_host,cname))
      lock.release()
      print "%s,%s,%s" % (CNAME_PREFIX,full_host,cname)
  except dns.resolver.NXDOMAIN:
    return
  except dns.resolver.NoNameservers:
    print "Info: dns.resolver.NoNameservers raised for CNAME '%s'" % full_host

def resolve_host_zdns(already,l,ext,sub,r,c,miscdata):
  actual_sub = ".".join(sub)
  if(actual_sub[-1:] == "."):
    actual_sub = actual_sub[0:len(actual_sub) - 1]
  full_host = "%s.%s.%s" % (actual_sub,ext.domain,ext.suffix)
  if full_host in already:
    print "Already resolved %s, skipping" % full_host
    return
  global resolveFile
  if resolveFile == None:
    resolveFile = open("%s.lst" % str(uuid.uuid4()),"w")
  resolveFile.write("%s\n" % full_host)

def resolve_host(already,l,ext,sub,r,c,miscdata):
  global threadHandler
  # print r
  actual_sub = ".".join(sub)
  if(actual_sub[-1:] == "."):
    actual_sub = actual_sub[0:len(actual_sub) - 1]
  full_host = "%s.%s.%s" % (actual_sub,ext.domain,ext.suffix)
  # print full_host
  if full_host in already:
    print "Already resolved %s, skipping" % full_host
    return
  while len(threadHandler) > THREADS_MAX:
    # print "Waiting for threads to exit..."
    threadHandler.pop().join()
  t = Thread(target=_threaded_resolve,args=(l,miscdata,r,full_host))
  t.daemon = True
  threadHandler.append(t)
  t.start()

def add_resolvedname(hostname):
  global alt_words
  w = hostname[0:hostname.index(".")]
  if w not in alt_words:
    alt_words.append(w)
    dns_words = open("words.txt","a")
    dns_words.write(hostname[0:hostname.index(".")]+"\n")
    dns_words.close()

def resolveCached(resolved_list):
  global resolveFile
  if resolveFile == None:
    print "resolveCached somehow called with no resolveFile. FIXME, halting"
    sys.exit(-1)
  resolveFile.close()
  tempfile = modules.zdns.runScan(os.path.basename(resolveFile.name))
  modules.zdns.parseJson(tempfile,resolved_list)
  os.remove(tempfile)
  os.remove(os.path.basename(resolveFile.name))
  # refresh the resolve file...
  resolveFile = None

def mutate(base_urls,c,scope_tlds):
  global alt_words
  global lock
  global threadHandler
  global ZDNS_BACKEND
  global NAMESERVER_LIST
  lock = Lock()
  threadHandler = []
  # TODO: round-robin using multiple resolver pools
  r = dns.resolver.Resolver()
  r.nameservers = NAMESERVER_LIST
  # print r.nameservers
  # sys.exit(0)
  resolve_success = []
  # c.execute("select * from resolved")
  already_resolved = []
  misc = []
  for base in base_urls:
    try:
      if base in already_resolved:
        ip = None
      else:
        ip = r.query(base,"A")[0]
    except:
      ip = None
    if ip is not None:
      print "%s,%s,%s" % (RESOLVE_PREFIX,base,ip)
      c.addARecord(base,ip)
      # c.execute("insert or ignore into resolved values (\"%s\",\"%s\")" % (base, ip))
    wildcard_check = str(uuid.uuid4()) + "." + base
    # print "Testing for wildcard DNS: %s" % wildcard_check
    ip = None
    try:
      ip = r.query(wildcard_check,"A")[0]
    except:
      ip = None
    if ip is not None:
      print "Wildcard DNS found, skipping loop"
      continue
    ext = tldextract.extract(base)
    sub = ext.subdomain.split(".")
    print "TRYING NEW CORE SUBDOMAIN: %s" % ext.domain
    if ext.domain in core.blacklist.BLACKLIST:
      print "Info: Base %s is in blacklist, ignoring" % ext.domain
      continue
    if ext.domain not in c.scope:
      print "Info: Base %s is not in scope, ignoring" % ext.domain
      continue
    resolverfunc = resolve_host
    if ZDNS_BACKEND == True:
      resolverfunc = resolve_host_zdns
    # for the below:
    # ---------------------
    # r is the resolver
    # c is the core/db.py object
    # misc is a list for storing non-A-records
    # resolve_success is a list of IP addresses
    # already_resolved is the resolutions we've already made, 
    # sub,ext make up the full hostname (relic from altdns i think)
    for word in alt_words:
      for index in range(0, len(sub)):
        sub.insert(index, word)
        resolverfunc(already_resolved,resolve_success,ext,sub,r,c,misc)
        sub.pop(index)
        original_sub = sub[index]
        if len(original_sub) > 0:
          sub[index] = sub[index] + "-" + word
          resolverfunc(already_resolved,resolve_success,ext,sub,r,c,misc)
          sub[index] = word + "-" + original_sub
          resolverfunc(already_resolved,resolve_success,ext,sub,r,c,misc)
          sub[index] = original_sub + word 
          resolverfunc(already_resolved,resolve_success,ext,sub,r,c,misc)
          sub[index] = word + original_sub
          resolverfunc(already_resolved,resolve_success,ext,sub,r,c,misc)
          sub[index] = original_sub
    # print "Waiting for thread pool to empty (%d)" % len(threadHandler)
    while len(threadHandler) > 0:
      # print "Waiting for thread pool to empty (%d)" % len(threadHandler)
      threadHandler.pop().join()
  if ZDNS_BACKEND == True:
    resolveCached(resolve_success)
  for (host,cname) in misc:
    c.addCnameRecord(host,cname)
  print "Flushing %d hosts into DB" % len(resolve_success)
  resolve_success = list(set(resolve_success))
  # print "Found %d unique hosts" % len(resolve_success)
  for (host,ip) in resolve_success:
    add_resolvedname(host)
    c.addARecord(host,ip)
    # c.execute("insert or ignore into resolved values(\"%s\",\"%s\")" % (host, ip))
    if host in base_urls:
      resolve_success.remove( (host,ip) )
      continue
    base_domain = tldextract.extract(host)
    # new_toplev = "%s.%s" % (base_domain.domain,base_domain.suffix)
    if base_domain.domain not in scope_tlds:
      print "Rejecting host %s as out of scope" % host
      resolve_success.remove( (host,ip) )    
  return resolve_success

def _threaded_scan(c,host,ip,port):
  global q
  global SCAN_PREFIX
  portnum = int(port)
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.settimeout(0.75)
  r = s.connect_ex((ip,portnum))
  if r == 0:
    q.put((ip,port))
    print "%s,%s,%s" % (SCAN_PREFIX,ip,port)

def light_scan(c,tc = 5):
  global q
  scannedlist = []
  # c.execute("create table if not exists scanned (host vartext, port vartext)")
  try:
    c.execute("select * from resolved group by ip")
  except:
    print "Error: database does not contain a 'resolved' table. Try brute forcing DNS first, or add values in the form (host vartext, ip vartext)."
    sys.exit(0)
  for (name,ip) in c.getAllResolved():
    if ip in scannedlist:
      continue
    else:
      scannedlist.append(ip)
    print "Scanning IP: %s" % ip
    portlist = [21,80,443,8080,8443,8081]
    threadlist = []
    for pn in portlist:
      t = Thread(target = _threaded_scan,args=(c,name,ip,pn))
      t.daemon = True
      threadlist.append(t)
      t.start()
    while len(threadlist) > 0:
      threadlist.pop().join()
    while q.empty() is False:
      (ip,port) = q.get()
      c.execute("insert or ignore into scanned values (\"%s\",%s)" % (ip,port))

def usage():
  print "usage: ./navigator.py [args] [domains]"
  print " --help: display this message"
  print " --no-dns: do NOT attempt to resolve dns names (default: yes, do dns)"
  print " --no-recurse: do NOT recurse DNS (default: yes)"
  print " --do-vhosts: attempt to brute force vhosts (default: no)"
  print " --do-scan: attempt to scan for live ips (default: no)"
  print " --db dbname: use the specified database name"
  print " --diff: compare results against previous run"
  print " --wordlist / -w wordlist: use custom wordlist file (default: words.txt)"
  print " --plugin pluginname: call 'modules.pluginname()'"

def load_plugins():
  for d in glob.glob("./modules/*.py"):
    r = d[2:].replace("/",".").rstrip(".py")
    if "__init__" not in r:
      globals()[r] = importlib.import_module(r)

if __name__ == "__main__":
  load_plugins()
  if len(sys.argv) < 2:
    usage()
    sys.exit(0)
  pluginlist = []
  master_list = []
  do_dns = True
  do_vhosts = False
  recurse_dns = True
  do_scan = False
  db = None
  overwrite_dns = False
  arg_index = 1
  while arg_index < len(sys.argv):
    arg = sys.argv[arg_index]
    # print arg
    if arg in ("-h","--help"):
      usage()
      sys.exit(0)
    elif arg in ("-zdns","--zdns"):
      ZDNS_BACKEND = True
    elif arg in ("--override-dns","--overwrite-dns"):
      overwrite_dns = True
    elif arg in ("--diff"):   # this only affects some functionality.
      DIFF_MODE = True        # currently, this only diffs DNS (and overwrites your DNS db)
    elif arg in ("--no-dns"):
      if do_dns == True:
        do_dns = False
      else:
        print "Error: trying to set do_dns twice. Fix argv"
        sys.exit(0)
    elif arg in ("--vhosts","--do-vhosts"):
      if do_vhosts == False:
        do_vhosts = True
      else:
        print "Error: trying to set do_vhosts twice. Fix arg"
        sys.exit(0)
    elif arg in ("--scan","--do-scan"):
      if do_scan == False:
        do_scan = True
      else:
        print "Error: trying to set do_scan twice. Fix arg"
        sys.exit(0)
    elif arg in ("--db","-db") and (arg_index + 1) != len(sys.argv):
      db = sys.argv[arg_index + 1]
      arg_index += 1
    elif arg in ("--wordlist","-w") and (arg_index + 1) != len(sys.argv):
      WORDS_FILE = sys.argv[arg_index + 1]
      arg_index += 1
    elif arg in ("--nameserver","-ns") and (arg_index + 1) != len(sys.argv):
      NAMESERVER_LIST.append(sys.argv[arg_index + 1])
      arg_index += 1
    elif arg in ("--plugin","-plugin") and (arg_index + 1) != len(sys.argv):
      pluginlist.append(sys.argv[arg_index + 1])
      arg_index += 1
    else:
      master_list.append(arg) 
    arg_index += 1
  # print pluginlist
  # sys.exit(0)
  if do_dns and db != None:
    if os.path.exists(db) and os.path.isfile(db):
      if overwrite_dns:
        print "Warning: this operation will overwrite DNS"
      else:
        print "Warning: you supplied an existing DB, and did not override DNS. switching off DNS resolution"
        do_dns = False
  if not (do_dns or do_scan or do_vhosts) and len(pluginlist) == 0:
    print "Error: do_dns == False, do_scan == False, do_vhosts == False, no plugins. What do you want?"
    sys.exit(0)
  if len(master_list) == 0:
    print "FIXME: No master domain list specified. This should be fine, IF an existing db is specified AND it's pre-seeded."
    sys.exit(0)
  for m in master_list:
    if not (os.path.exists(m) and os.path.isfile(m)):
      print "Error: %s doesn't exist" % m
      sys.exit(0)
  if db == None:
    print "Info: --db: not set, using default name of %s.db" % (master_list[0])
    db = "%s.db" % master_list[0]
  c = core.db.NavigatorDB(db)
  c.initDB()
  # conn = sqlite3.connect(db)
  # c = conn.cursor()
  # if do_dns and 
  if do_dns == True:
    if not (os.path.exists(WORDS_FILE) and os.path.isfile(WORDS_FILE)):
      print "Error: %s is not a valid wordlist. Bye!" % WORDS_FILE
      sys.exit(0)
    dns_wordlist = open(WORDS_FILE,"r") 
    alt_words = [word.rstrip() for word in dns_wordlist.readlines() ]
    dns_wordlist.close()
    url_list = []
    for m in master_list:
      f = open(m,"r")
      for url in f.readlines():
        url_list.append(url.rstrip())
      f.close()
    print "Ok, loaded %d base URLs" % len(url_list)
    scope_tlds = []
    for i in url_list:
      base_domain = tldextract.extract(i)
      base_toplev = "%s.%s" % (base_domain.domain,base_domain.suffix)
      if base_domain.domain not in scope_tlds:
        c.addScope(base_domain.domain)
        scope_tlds.append(base_domain.domain)
    print "Info: You have %d TLD's in scope" % len(c.scope)
    resolved_list = mutate(url_list,c,scope_tlds)
    print "Found %d hosts" % len(resolved_list)
    total_count = len(resolved_list)
    c.commit()
    if recurse_dns:
      while len(resolved_list) != 0:
        new_resolved_list = mutate(list(set([x for (x,y) in resolved_list])),c,scope_tlds)
        c.commit()
        print "Recursive search found %d additional hosts" % len(new_resolved_list)
        total_count += len(new_resolved_list)
        resolved_list = new_resolved_list
    print "Successfully resolved %d names" % len(resolved_list)
  if do_scan == True:
    light_scan(c)
  if do_vhosts == True:
    modules.web.scan_vhosts(c)
  # print globals()
  for p in pluginlist:
    safe_p = p.replace("(","") # lol shit
    # print modules.web.scan_vhosts
    d = eval("callable(%s)" % safe_p) 
    if d == True:
      # print "Calling %s(c)" % safe_p
      exec("%s(c)" % safe_p)
    else:
      print "Warning: the plugin %s is not callable. skipping..."
      continue
  c.commit()
  c.close()

print "time elapsed: %d" % (time.time() - starttime)
