#!/usr/bin/python

# DCEPT
# James Bettke
# Dell SecureWorks 2016

import GenerationServer
from Cracker import cracker
import pyshark
import os
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

import urllib
import urllib2
import socket

# Globals
genServer = None

class DceptError(Exception):
	def __init__(self, message=""):
		Exception.__init__(self,message)

def kerbsniff(interface, username, domain, realm):

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
		except KeyError as e:
			pass
		
		

		# Only attempt to decrypt a password or notify master if we find an encrypted timestamp
		if encTimestamp:

			if config.master_node:
				notifyMaster(username, domain, encTimestamp)
			else:
				cracker.enqueueJob(username, domain, encTimestamp, passwordHit)


def notifyMaster(username, domain, encTimestamp):
	url = 'http://%s/notify' % (config.master_node)
	values = {	'u' : username,
					'd' : domain,
					't' : encTimestamp
				}
	data = urllib.urlencode(values)

	try:
		req = urllib2.Request(url, data)
		response = urllib2.urlopen(req, timeout=30)
	except (urllib2.URLError, socket.timeout) as e:
		message = "DCEPT slave Failed to communicate with master node '%s'" % (config.master_node)
		logging.error(message)
		alert.sendAlert(message)
		return False
	return True

def passwordHit(genServer, password):

	if password:
		record = genServer.findPass(password)
		message = "[RED ALERT] Honeytoken for %s\\%s '%s' was stolen from %s on %s" % \
			(record[1],record[2], record[4], record[3], record[0].split(" ")[0] )
		#print "\x1b[91m" + message + "\x1b[0m"
		print "\x1b[91m" + "[RED ALERT]" + "\x1b[0m"
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
	
	# Server roles for multi-server topology
	if not config.master_node:
		logging.info('Server configured as master node')
	else:
		logging.info('Server configured as slave node')

		# Test Connection to master node

	# Sanity check - Check if the interface is up
	if not testInterface(config.interface):
		logging.error("Unable to listen on '%s'. Is the interface up?" % (config.interface))
		raise DceptError()

	logging.info('Starting DCEPT...')

	# Only master node should run the generation server and cracker 
	if not config.master_node: # (Master Node)

		# Spawn and start the password generation server
		try:
			global genServer 
			genServer = GenerationServer.GenerationServer(config.honeytoken_host, config.honeytoken_port)
		except socket.error as e:
			logging.error(e)
			logging.error("Failed to bind honeytoken HTTP server to address %s on port %s" % (config.honeytoken_host, config.honeytoken_port))
			raise DceptError()

		# Initialize the cracker
		cracker.start(genServer)

	else: # (Slave Node)
		# Test sending notifications to the master node
		logging.info("Testing connection to master node '%s'" % (config.master_node))
		if not notifyMaster('u', 'd', 't'):
			raise DceptError()

	# Start the sniffer (Both master and slave)
	try:
		kerbsniff(config.interface,config.honey_username, config.domain, config.realm)
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

