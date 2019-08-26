#!/usr/bin/python

print "Module 'core.db' loaded"

import sys
import sqlite3
import time

class NavigatorDB:
  def __init__(self,dbname):
    self.conn = sqlite3.connect(dbname)
    self.c = self.conn.cursor()
    self.initialized = False
    self.scope = []
    print "Info: NavigatorDB module loaded. Don't forget to initialize..."
    # print "ok, self.c is good"

  def execute(self,stmt):
    print "FIXME: execute %s" % stmt
    self.c.execute(stmt) 

  def commit(self):
    return self.conn.commit()

  def close(self):
    self.conn.commit()
    self.conn.close()
    return

  # manually add scope and filter URLs from 
  # this point (i.e. stop saving incapdns records
  # to main db
  def addScope(self,tld):
    if self.initialized == False:
      print "Fatal: attempting to addCnameRecord to an uninitialized core/db session. Use core.db.iAcceptTheRisk() if you're absolutely sure"
      sys.exit(0)
    if tld not in self.scope:
      self.scope.append(tld)
      self.c.execute("insert or ignore into scope values (\"%s\")" % tld)

  def getAllResolved(self):
    self.c.execute("select * from resolved;")
    return self.c.fetchall()

  def iAcceptTheRisk(self):
    print "Warning: core.db.iAcceptTheRisk() called. You're on your own."
    self.initialized = True
    return

  # this is meant to be called once for each session
  # so each DB can store historical data.
  def initDB(self):
    self.c.execute("select name from sqlite_master where type='table' and name='__navigator_data'")
    r = self.c.fetchall()
    if(len(r) == 0):
      print "Info: Uninitialized database. Initializing."
      # first, create and populate the internal metadata tables
      self.c.execute("create table if not exists __navigator_data (name varchar not null, data varchar not null)")
      self.c.execute("create table if not exists __navigator_history (ticks integer not null, date varchar not null)")
      # now, create the 'resolved' table
      self.c.execute("create table if not exists resolved (host varchar not null, ip varchar not null)")
      self.c.execute("create table if not exists scanned (host vartext, port vartext)")
      self.c.execute("create table if not exists cnames (host vartext, cname vartext)")
      self.c.execute("insert into __navigator_history values (%d,\"%s\")" % (int(time.time()), time.strftime("%Y-%m-%d %H:%M:%S",time.gmtime(time.time()))) )
      self.conn.commit()
      self.c.execute("create table if not exists scope (host vartext)")
      # sys.exit(0)
    else:
      print "Info: Loading pre-initialized database. Creating new session..."
      self.c.execute("select * from __navigator_history order by ticks desc")
      (ticks,timestamp) = self.c.fetchone()
      # todo - someth ing something archival (see post-it note)
      self.c.execute("select count(*) from resolved")
      countRowsResolved = self.c.fetchone()[0]
      self.c.execute("alter table resolved rename to resolved_%d" % ticks)
      self.c.execute("alter table scanned rename to scanned_%d" % ticks)
      self.c.execute("alter table cnames rename to cnames_%d" % ticks)
      self.conn.commit()
      self.c.execute("create table if not exists resolved (host varchar not null, ip varchar not null)")
      self.c.execute("create table if not exists scanned (host vartext, port vartext)")
      self.c.execute("create table if not exists cnames (host vartext, cname vartext)")
      self.c.execute("insert into __navigator_history values (%d,\"%s\")" % (int(time.time()), time.strftime("%Y-%m-%d %H:%M:%S",time.gmtime(time.time()))) )
      self.conn.commit()
      self.c.execute("select * from scope")
      for scopetld in self.c.fetchall():
        self.scope.append(scopetld)
    self.initialized = True
    return

  def addCnameRecord(self,host,cname):
    if self.initialized == False:
      print "Fatal: attempting to addCnameRecord to an uninitialized core/db session. Use core.db.iAcceptTheRisk() if you're absolutely sure"
      sys.exit(0)
    self.c.execute("insert or ignore into cnames values (\"%s\",\"%s\")" % (host,cname))
    return

  def addARecord(self,host,ip):
    if self.initialized == False:
      print "Fatal: attempting to addCnameRecord to an uninitialized core/db session. Use core.db.iAcceptTheRisk() if you're absolutely sure"
      sys.exit(0)
    self.c.execute("insert or ignore into resolved values (\"%s\",\"%s\")" % (host,ip))
    return
