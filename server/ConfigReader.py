#!/usr/bin/python

# James Bettke
# Dell SecureWorks 2016

import logging
import ConfigParser
import StringIO

class ConfigError(Exception):
	def __init__(self, message=""):
		Exception.__init__(self,message)

class ConfigReader():

	def __init__(self):
		self.setDefaults()

	def load(self, path):
		parser = ConfigParser.SafeConfigParser()
		
		try:
			cfg_str = '[root]\n' + open(path, 'r').read()
			cfg_fp = StringIO.StringIO(cfg_str)
			parser = ConfigParser.RawConfigParser(allow_no_value=False)
			parser.readfp(cfg_fp)

			self.__dict__.update(parser.items("root"))

		except (ConfigParser.ParsingError) as e:
			error = str(e)
			line = error[error.find("[line")+5:error.find("]")].strip()
			raise ConfigParser.ParsingError("Failed to parse config file. Error on line: " + line)

		self.checkConfig()

	def setDefaults(self):
		self.honeytoken_host		= "0.0.0.0"
		self.honeytoken_port		= 80
		self.honeytoken_param_name  = "machine"
		self.interface				= None 
		self.domain  				= None
		self.realm  				= None
		self.honey_username			= None
		self.smtp_host 				= None
		self.smtp_port				= 25
		self.email_address 			= None
		self.subject				= "DCEPT IDS Triggered - Immediate Action Necessary"
		self.syslog_host			= None
		self.syslog_port			= 514
		self.log_level 				= "INFO"

	
	def checkConfig(self):

		if not self.interface:
			raise ConfigError("You must configure an interface")

		if not self.domain:
			raise ConfigError("You must configure a domain")

		if not self.domain:
			raise ConfigError("You must configure a realm")

		if not self.honey_username:
			raise ConfigError("You must configure a honeytoken username")

		if self.log_level.upper() not in {"CRITICAL","ERROR","WARNING","INFO","DEBUG","NOTSET"}:
			raise ConfigError("Invalid setting for log level")
		else:
			level = logging.getLevelName(self.log_level.upper())
			logging.getLogger().setLevel(level)
			
			

config = ConfigReader()

