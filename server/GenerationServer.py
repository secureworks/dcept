#!/usr/bin/python

# DCEPT
# James Bettke
# Dell SecureWorks 2016

import BaseHTTPServer
import urlparse
import random
from datetime import datetime
import os
import sqlite3
import threading
import logging
from ConfigReader import config

# https://wiki.python.org/moin/BaseHttpServer

gsHandle = None

class GenerationServer:

	def __init__(self, hostname="", http_port=80, sqlite_path='/opt/dcept/var/honeytoken.db'):
		server_class = BaseHTTPServer.HTTPServer
		self.httpd = server_class((hostname, http_port), HttpHandler)
		
		global gsHandle
		gsHandle = self
		
		self.sqlite_path = sqlite_path 
		self.conn = None
		self.initDatabase()

		# Start the webserver
		thread = threading.Thread(target = self.httpd.serve_forever)
		thread.daemon = True
		logging.info("Starting honeytoken generation server HTTP daemon %s:%d" % (hostname,http_port))
		thread.start()


	# Initialize the sqlite database. Create the db and tables if it doesn't exist.
	def initDatabase(self):
		if not os.path.exists(self.sqlite_path):
			self.conn = sqlite3.connect(self.sqlite_path, check_same_thread=False)
			c = self.conn.cursor()
			c.execute('''CREATE TABLE db_version (major integer, minor integer)''')
			c.execute("INSERT INTO db_version VALUES (?,?)", (1,0))

			c.execute('''CREATE TABLE logs
				 (date text, domain text, username text, machine text, password text)''')

			# Add a test honeytoken to the database
			c.execute("INSERT INTO logs VALUES (?,?,?,?,?)", (datetime.now(), "ALLSAFE.LAN", "Administrator", "FAKE-PC", "dcepttest"))
			self.conn.commit()
		else:
			self.conn = sqlite3.connect(self.sqlite_path, check_same_thread=False)


	def genPass(self):
		alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		password = ""

		while True:
	 
			# Create a random password using the above alphabet
			for i in xrange(10):
				password += alpha[random.randrange(len(alpha))]

			print "Generated -",password

			# Does this password already exist?
			if self.findPass(password) == None:
				break
			else:
				print "Password collision, regenerating..."

		return password


	def findPass(self, password):
		c = self.conn.cursor()
		c.execute("SELECT * FROM logs WHERE password=?" , (password,))
		row = c.fetchone()

		if row == None:
			return None
		return row


	def getPasswords(self):
		c = self.conn.cursor()
		c.execute("SELECT password FROM logs ORDER BY date DESC")

		passwords = []
		for i in c.fetchall():
			passwords.append(i[0])
		return passwords

class HttpHandler(BaseHTTPServer.BaseHTTPRequestHandler):


	def do_GET(s):

		global gsHandle

		#if not s.path.startswith("/backup"):
		#	s.send_response(404)
		#	return

		s.send_response(200)
		s.send_header("Content-type", "text/json")
		s.end_headers()

		#print s.path
		qs = urlparse.urlparse(s.path).query
		qs = urlparse.parse_qs(qs)
		#print qs
		machine = ""
		try:
			machine = qs['machine'][0]
		except:
			return
		print "Request from:",machine

		domain = config.domain 
		username = config.honey_username

		password = gsHandle.genPass()
		jSONstring = "{'d':'%s','u':'%s',p:'%s'}" % (domain, username, password)
		s.wfile.write(jSONstring)
		print "Sent:"+jSONstring

        # Log transaction
		c = gsHandle.conn.cursor()
		c.execute("INSERT INTO logs VALUES (?,?,?,?,?)", (datetime.now(), domain, username, machine, password))
		gsHandle.conn.commit()


if __name__ == '__main__':
	gs = GenerationServer()
