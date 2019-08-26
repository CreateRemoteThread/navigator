#!/usr/bin/python

import zmq
import time
import os
from threading import Thread

context = zmq.Context()

class ReportingThread(Thread):
  def __init__(self):
    Thread.__init__(self)
    self.socket = context.socket(zmq.REP)
    self.socket.bind("tcp://127.0.0.1:19992")
  
  def run(self):
    while True:
      message = self.socket.recv()
      print "got: %s" % message
      self.socket.send("ack") 

class QueueThread(Thread):
  def __init__(self):
    Thread.__init__(self)
    self.socket = context.socket(zmq.PUB)
    self.socket.bind("tcp://127.0.0.1:19991")

  def run(self):
    while True:
      self.socket.send("1 1")
      time.sleep(1)

print "Starting MQ Master (pid %d)" % os.getpid()

myThread1 = ReportingThread()
myThread1.start()

myThread2 = QueueThread()
myThread2.start()

myThread1.join()
myThread2.join()


