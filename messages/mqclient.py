#!/usr/bin/python

import zmq
import time
import sys
from threading import Thread

context = zmq.Context()

class RequestThread(Thread):
  def __init__(self):
    Thread.__init__(self)
    self.socket = context.socket(zmq.REQ)
    self.socket.connect("tcp://127.0.0.1:19992")
  
  def run(self):
    while True:
      self.socket.send(sys.argv[1])
      self.socket.recv()
      time.sleep(5)

class QueueThread(Thread):
  def __init__(self):
    Thread.__init__(self)
    self.socket = context.socket(zmq.SUB)
    self.socket.connect("tcp://127.0.0.1:19991")
    self.socket.setsockopt(zmq.SUBSCRIBE,"1")

  def run(self):
    while True:
      print self.socket.recv()

rt = RequestThread()
rt.start()

qt = QueueThread()
qt.start()

rt.join()
qt.join()

print "client exiting"
