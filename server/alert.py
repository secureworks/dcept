#!/usr/bin/python

# James Bettke
# Dell SecureWorks 2016

from ConfigReader import config
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText

import logging
from logging import *
import logging.handlers


import socket

def sendAlert(message):

	if config.smtp_host:
		sendEmail(config.smtp_host, config.email_address, config.subject, message, config.smtp_port)

	if config.syslog_host:
		sendSyslog(config.syslog_host, message, 1, 4, config.syslog_port)


def sendSNMP(host, message, port=162, version=2):
	pass


# Sends a single syslog message UDP packet. See RFC3164 
def sendSyslog(host, message, severity=1, facility=4, port=514):
	#severity = 1 - Alert: Action must be taken immediately
	#facility = 4 - security/authorization messages
	
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	data = '<%d>%s' % (severity + facility*8, message)
	sock.sendto(data, (host, port))
	sock.close()	
	#rsyslog = logging.handlers.SysLogHandler(address=(host, port), facility=logging.handlers.SysLogHandler.LOG_USER, socktype=socket.SOCK_DGRAM)
	#rsyslog.critical(message)

# Send an email notification to authenticated SMTP server
def sendEmail(smtp_host, emailAddress, subject, message, port=25):
	msg = MIMEMultipart()
	msg['Subject'] = subject
	msg['From'] = "dcept_ids"
	msg['To'] = emailAddress
	text = message

	msg.attach(MIMEText(text, 'plain'))

	s = smtplib.SMTP(smtp_host, port)
	s.sendmail("DCEPT", emailAddress, msg.as_string())
	s.quit()

if __name__ == "__main__":
	sendSyslog("127.0.0.1", "DCEPT Alert")
	sendEmail("127.0.0.1", "dcept@local.lan", "DCEPT Alert")
