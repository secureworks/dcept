#!/usr/bin/python

# DCEPT
# James Bettke
# Dell SecureWorks 2016

import logging
import Queue
import threading
import tempfile
import shutil
import subprocess
import time

class Cracker:

	def __init__(self):
		self.passwordQueue = Queue.Queue(maxsize=100)
		self.thread = threading.Thread(target = self._run, args = ())
		self.thread.daemon = True

	def enqueueJob(self, username, domain, encTimestamp, callback):
		self.passwordQueue.put((username, domain, encTimestamp, callback))
		logging.debug("Cracker enqueued 1 encrypted timestamp. Queue size: %d" % (self.passwordQueue.qsize()))


	# Take the encrypted timestamp and recover the generated password using a 
	# password cracker. This should not take take very long since we are only 
	# interested in the short word list of passwords made by the generation server. 
	# It should crack the most recent passwords working backward. In practice the 
	# only time this subroutine is called is when someone uses the honeytoken 
	# domain\username. 
	def recoverPassword(self, username, domain, encTimestamp, callback):


		tmpDir = tempfile.mkdtemp("-dcept")

		wordPath = tmpDir + "/wordlist.tmp"
		passPath = tmpDir + "/encPass.tmp"
		potPath  = tmpDir + "/john.pot"

		logging.debug("Recovering password from encrypted timestamp...")
	
		# Create password file for cracking tool
		fh = open(passPath, 'w')
		fh.write("$%s$%d$%s$%s$$%s" % ("krb5pa",18,username, domain, encTimestamp))
		fh.close()
	
		# Create word list of the generated passwords ordered by most recent	
		fh = open(wordPath, 'w')
	
		wordlist = self.genServer.getPasswords()
		if len(wordlist) == 0:
			logging.info("Generation server hasn't issued any passwords. There is nothing to crack")
			return

		logging.info("Testing %d password(s)" % (len(wordlist)))
		fh.write("\n".join(wordlist))
		fh.close()

		redirectStr = ""
		if logging.getLogger().getEffectiveLevel() != logging.DEBUG:
			redirectStr = "2>/dev/null"

		result = subprocess.check_output("/opt/dcept/john --wordlist=%s --pot=%s --format=krb5pa-sha1 %s %s" % (wordPath, potPath, passPath, redirectStr), shell=True)

		print "Cracking job completed"
		shutil.rmtree(tmpDir)

		logging.debug(result)
		lines = result.split("\n")
	 
		success = False
		for line in lines:
			if line.endswith("(?)"):
				success = True
				password = line.split(" ")
				print "Cracked! Password: %s" % (password[0])
				callback(self.genServer, password[0])

	def start(self, genServer):
		self.genServer = genServer
		self.thread.start()

	def _run(self):
		while True:
			if not self.passwordQueue.empty():
				item = self.passwordQueue.get()
				self.recoverPassword(item[0], item[1], item[2], item[3])

# Singleton
cracker = Cracker()
