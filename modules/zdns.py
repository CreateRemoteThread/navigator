#!/usr/bin/env python

import sys
import json
import uuid
import os

ZDNS_PATH = "~/go/bin/zdns"
ZDNS_THREADCOUNT = 50

def runScan(scanFile):
  global ZDNS_PATH
  global ZDNS_THREADCOUNT
  tempfile = str(uuid.uuid4()) + ".lst"
  os.system("%s A -input-file %s -threads %d > %s" % (ZDNS_PATH,scanFile,ZDNS_THREADCOUNT,tempfile))
  return str(tempfile)

def parseJson(filename,l):
  data = []
  with open(filename) as f:
    data = f.readlines()
  if len(data) == 0:
    print "Could not parse JSON file %s" % filename
    sys.exit(0)
  data_clean = [x.rstrip() for x in data]
  for lol in data_clean:
    d = json.loads(lol)
    if d["status"] == "NOERROR" and d["class"] == "IN":
      for entry in d["data"]["answers"]:
        if entry["type"] == "A":
          name = entry["name"]
          ip = entry["answer"]
          data = (name,ip)
          print "_resolve_,%s,%s" % (name,ip)
          l.append(data)
          # print "%s:%s" % (name,ip)

print "Module 'zdns' Loaded"
