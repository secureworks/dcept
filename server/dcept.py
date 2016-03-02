#!/usr/bin/python

# DCEPT
# James Bettke
# Dell SecureWorks 2016

import GenerationServer
import pyshark
import os
import subprocess
import sys
import socket 

import logging
from logging import Logger
import ConfigParser
from ConfigReader import config
from ConfigReader import ConfigError

import pyshark
import pyiface
import alert

import threading
import tempfile
import shutil

class DceptError(Exception):
	def __init__(self, message=""):
		Exception.__init__(self,message)

def kerbsniff(interface, username, domain, realm, genServer):

	logging.info("kerbsniff: Looking for %s\%s on %s" % (domain,username,interface))
	
	filtered_cap = pyshark.LiveCapture(interface, bpf_filter='tcp port 88')
	packet_iterator = filtered_cap.sniff_continuously
	
	# Loop infinitely over packets if in continuous mode
	for packet in packet_iterator():

		# Is this packet kerberos?
		kp = None
		encTimestamp = None
		try:
			kp = packet['kerberos']

			# Extract encrypted timestamp for Kerberos Preauthentication packets
			# that conatin honeytoken domain\username
			encTimestamp = kerb_handler(kp,domain,username)
		except KeyError:
			pass
		

		# Only attempt to decrypt a password if we find an encrypted timestamp
		if encTimestamp:
			
			# Cracking takes awhile, so do this in another thread
			thread = threading.Thread(target = testPassword, args = (username, domain,  encTimestamp, genServer))
			thread.daemon = True
			thread.start()

 
				

def testPassword(username, domain,  encTimestamp, genServer):

	# Given the encrypted timestamp recover the generated password 
	password = recoverPassword(username, domain,  encTimestamp, genServer)

	if password:
		record = genServer.findPass(password)
		message = "[RED ALERT] Honeytoken for %s\\%s '%s' was stolen from %s on %s" % \
			(record[1],record[2], record[4], record[3], record[0].split(" ")[0] )
		print "\x1b[91m" + message + "\x1b[0m"
		logging.critical(message)			
		alert.sendAlert(message)


# Parse Kerberos packet and return the encrypted timestamp only if we detected 
# honeytoken usage (honey domain\username)
def kerb_handler(kp, domain,username):
	encTimestamp = None

	# We are looking for kerberos packets of message type: AS-REQ (10)
	#kp.pretty_print() 
	if kp.msg_type == "10":
	

		# Depending on the version of TShark installed, the krb 
		# dissector will display the username field under a different name
		try:
			kerbName = kp.name_string
		except AttributeError:
			pass

		try:
			kerbName = kp.kerberosstring
		except AttributeError:
			pass

		realm = kp.realm
		logging.debug("kerb-as-req for domain user %s\%s" % (realm, kerbName))

		if kerbName.lower() == username.lower() and realm.lower() == config.realm.lower():

			# Depending on the version of TShark installed, the krb 
			# dissector will display the encrypted field under a different name
			try:
				encTimestamp = kp.pa_enc_timestamp_encrypted.replace(":","")
			except AttributeError:
				pass

			try:
				encTimestamp = kp.cipher.replace(":","")
			except AttributeError:
				pass

			logging.debug("PA-ENC-TIMESTAMP: %s", encTimestamp)
		else:
			logging.debug("Ignoring kerb-as-req for '%s\%s'" % (realm,kerbName))
 

	else:
		logging.debug("Ignoring kerberos packet - Not kerb-as-req")

	return encTimestamp


# Take the encrypted timestamp and recover the generated password using a 
# password cracker.This should not take take very long since we are only 
# interested in the short word list of passwords made by the generation server. 
# It should crack the most recent passwords working backward. In practice the 
# only time this subroutine is called is when someone uses the honeytoken 
# domain\username. 
def recoverPassword(username, domain,  encTimestamp, genServer):


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
	
	wordlist = genServer.getPasswords()
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
	shutil.rmtree(tmpDir)

	logging.debug(result)
	lines = result.split("\n")
 
	for line in lines:
		if line.endswith("(?)"):
			password = line.split(" ")
			return password[0]



def testInterface(interface):
	try:
		iface = pyiface.Interface(name=interface)
		if iface.flags == iface.flags | pyiface.IFF_UP:
			return True
	except IOError as e:
		if e.errno == 19: # No such device
			print "Bad interface. No such device '%s'" % (interface)
	return False

def main():
	banner = """
	  _____   _____ ______ _____ _______ 
	 |  __ \ / ____|  ____|  __ |__   __|
	 | |  | | |    | |__  | |__) | | |   
	 | |  | | |    |  __| |  ___/  | |   
	 | |__| | |____| |____| |      | |   
	 |_____/ \_____|______|_|      |_|
"""
 
	print banner
	
	try:
		# Read the configuration file
		config.load("/opt/dcept/dcept.cfg")
	except (ConfigParser.Error, ConfigError) as e:
		logging.error(e)
		raise DceptError()
	
	# Sanity check - Check if the interface is up
	if not testInterface(config.interface):
		logging.error("Unable to listen on '%s'. Is the interface up?" % (config.interface))
		raise DceptError()

	logging.info('Starting DCEPT...')

	# Spawn and start the password generation server
	genServer = None
	try:
		genServer = GenerationServer.GenerationServer(config.honeytoken_host, config.honeytoken_port)
	except socket.error as e:
		logging.error(e)
		logging.error("Failed to bind honeytoken HTTP server to address %s on port %s" % (config.honeytoken_host, config.honeytoken_port))
		raise DceptError()

	
	try:
		kerbsniff(config.interface,config.honey_username, config.domain, config.realm, genServer)
	except pyshark.capture.capture.TSharkCrashException:
		
		logging.error(message)
		raise DceptError(message)
		

if __name__ == "__main__":

	try:
		# Setup logging to file for troubleshooting
		logging.basicConfig(filename='/opt/dcept/var/dcept.log',format='%(asctime)s %(levelname)s %(message)s')

		# Mirror logging to console
		logging.getLogger().addHandler(logging.StreamHandler())

		main()
	except	(KeyboardInterrupt, DceptError):
		print
		logging.info("Shutting down DCEPT...")

