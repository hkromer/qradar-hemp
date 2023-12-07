#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  qradar-hemp.py
#  
#  Copyright 2017 Hubert Kromer
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  

### CONFIGURATION ###

## BASIC ##
# Hostname or IP address of QRadar console, useful if qradar-hemp will
# not be executed on the console itself
qradarDeploymentConsole = 'localhost'
# Delay between configuration fetching in minutes
qradarDeploymentRefreshDelay = 15
# Target for logs created by HeMP, useful if qradar-hemp will not be
# executed on the console itself. In most cases should point at the
# console
syslogTargetCustom = ('127.0.0.1', 514)
# Delay between data polling
pollingTime = 180

## EXTENDED ##
# Services to be checked on all managed hosts / console / EC / FC
servicesQRadarAll = ['hostservices', 'hostcontext', 'postgresql']
servicesQRadarConsole = ['tomcat']
servicesQRadarEventCollector = ['ecs-ec', 'ecs-ep']
servicesQRadarQFlowCollector = ['qflow']

# Appliance types, in case new would be added
qradarApplianceTypeAllInOne = [21, 31]
qradarApplianceTypeEventCollector = [15, 16]
qradarApplianceTypeQFlowCollector = [12, 13, 17, 18]

### END OF CONFIGURATION ###

# Import required libraries
import os
import socket
import sys
import time
import subprocess
import re
import logging
import logging.handlers
import StringIO
import psycopg2
import ConfigParser
from xml.dom import minidom

# The function below is required as QRadar prior to 7.3 is using Python in version 2.6.
# subprocess.check_output was introduced in Python 2.7.
if "check_output" not in dir(subprocess):
	def check_output(*popenargs, **kwargs):
		process = subprocess.Popen(stdout=subprocess.PIPE, *popenargs, **kwargs)
		output, unused_err = process.communicate()
		retcode = process.poll()
		if retcode:
			cmd = kwargs.get("args")
			if cmd is None:
				cmd = popenargs[0]
			error = subprocess.CalledProcessError(retcode, cmd)
			error.output = output
			raise error
		return output

	subprocess.check_output = check_output

# Check if the app is already running
def isAlreadyRunning():
	isAlreadyRunning._lock_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
	try:
		isAlreadyRunning._lock_socket.bind('\0' + 'qradar-hemp')
	except socket.error:
		sys.exit()

# Check if current host is QRadar console
def isCurrentConsole():
	if os.path.isfile('/opt/qradar/conf/nva.conf') == True:
		confNva = StringIO.StringIO()
		confNva.write('[config]\n')
		confNva.write(open('/opt/qradar/conf/nva.conf').read())
		confNva.seek(0, os.SEEK_SET)
		confNvaFixed = ConfigParser.RawConfigParser()
		confNvaFixed.readfp(confNva)
		if confNvaFixed.get('config', 'CONSOLE_HOSTNAME') == re.split('[- .]',socket.gethostname())[0]:
			return True
	return False

# Define the target for logs
def syslogTarget():
	if isCurrentConsole() == True:
		return ('localhost', 514)
	return syslogTargetCustom

# Setup logging
log = logging.getLogger(socket.gethostname())
log.setLevel(logging.DEBUG)
logTarget = syslogTarget()
logHandler = logging.handlers.SysLogHandler(address=logTarget)
logFormatter = logging.Formatter(' %(asctime)s 127.0.0.1 [%(threadName)s] com.q1labs.qradar.hemp.Agent: [%(levelname)s] [NOT:0000006000] [127.0.0.1/- -] [-/- -]LEEF:1.0|QRadar|Health Agent|7.2.4|QRadarHealthMetric|%(message)s', datefmt='%b %d %H:%M:%S')
logHandler.setFormatter(logFormatter)
log.addHandler(logHandler)

# Enable for debugging, all messages will go to a specified log file
#logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s', datefmt='%b %d %H:%M:%S', filename='/var/tmp/qradar-hemp.log', filemode='w')

# Fetch the deployment configuration from QRadar
def qradarDeploymentFetch():
	if isCurrentConsole() == True:
		qradarDeploymentConf = minidom.parse('/opt/qradar/conf/deployment.xml')
		qradarDeploymentHosts = qradarDeploymentConf.getElementsByTagName('managedHost')
	else:
		if os.path.isfile('/var/tmp/deployment.xml') == True:
			if time.time() - os.path.getmtime('/var/tmp/deployment.xml') > (qradarDeploymentRefreshDelay * 60):
				fetchCommand = subprocess.Popen(['scp', '%s:/opt/qradar/conf/deployment.xml' % qradarDeploymentConsole, '/var/tmp/deployment.xml'])
				fetchLock = fetchCommand.wait()
		else:
			fetchCommand = subprocess.Popen(['scp', '%s:/opt/qradar/conf/deployment.xml' % qradarDeploymentConsole, '/var/tmp/deployment.xml'])
			fetchLock = fetchCommand.wait()
		qradarDeploymentConf = minidom.parse('/var/tmp/deployment.xml')
		qradarDeploymentHosts = qradarDeploymentConf.getElementsByTagName('managedHost')
	return qradarDeploymentHosts

def qradarDeploymentIdFetch():
	if isCurrentConsole() == True:
		confNva = StringIO.StringIO()
		confNva.write('[config]\n')
		confNva.write(open('/opt/qradar/conf/nva.conf').read())
		confNva.seek(0, os.SEEK_SET)
		confNvaFixed = ConfigParser.RawConfigParser()
		confNvaFixed.readfp(confNva)
		qradarDeploymentId = confNvaFixed.get('config', 'DEPLOYMENT_ID')
	else:
		if os.path.isfile('/var/tmp/nva.conf') == True:
			if time.time() - os.path.getmtime('/var/tmp/nva.conf') > (qradarDeploymentRefreshDelay * 60):
				fetchCommand = subprocess.Popen(['scp', '%s:/opt/qradar/conf/nva.conf' % qradarDeploymentConsole, '/var/tmp/nva.conf'])
				fetchLock = fetchCommand.wait()
		else:
			fetchCommand = subprocess.Popen(['scp', '%s:/opt/qradar/conf/nva.conf' % qradarDeploymentConsole, '/var/tmp/nva.conf'])
			fetchLock = fetchCommand.wait()
		confNva = StringIO.StringIO()
		confNva.write('[config]\n')
		confNva.write(open('/var/tmp/nva.conf').read())
		confNva.seek(0, os.SEEK_SET)
		confNvaFixed = ConfigParser.RawConfigParser()
		confNvaFixed.readfp(confNva)
		qradarDeploymentId = confNvaFixed.get('config', 'DEPLOYMENT_ID')
	return qradarDeploymentId

# Report the metric to Syslog
def logMetric(metricId, deploymentId, hostName, componentName, value):
	if value == False:
		log.critical('MetricID=%s DeploymentID=%s HostName=%s ComponentType=qradar-hemp ComponentName=qradar-hemp Element=%s Value=%s' % (metricId, deploymentId, hostName, componentName, value))
	else:
		log.info('MetricID=%s DeploymentID=%s HostName=%s ComponentType=qradar-hemp ComponentName=qradar-hemp Element=%s Value=%s' % (metricId, deploymentId, hostName, componentName, value))
	return 0
	

# Check if host is using 'systemd' already
def isSystemd(host):
	devNull = open(os.devnull)
	try:
		output = subprocess.check_output(['ssh', host, 'systemctl'], stderr=devNull, shell=False)
	except subprocess.CalledProcessError as outputStatus:
		outputReturnCode = outputStatus.returncode
	if outputReturnCode == 0:
		return True
	return False

# Check the service status
def isServiceRunning(host, service):
	devNull = open(os.devnull)
	if isCurrentConsole():
		if isSystemd(host):
			output = None
			try:
				output = subprocess.check_output(['ssh', host, 'systemctl', 'status', service], stderr=devNull, shell=False)
			except subprocess.CalledProcessError as e:
				output = e.output
		else:
			output = None
			try:
				output = subprocess.check_output(['ssh', host, 'service', service, 'status'], stderr=devNull, shell=False)
			except subprocess.CalledProcessError as e:
				output = e.output
		if 'running' in output:
			return True
	else:
		if isSystemd( qradarDeploymentConsole ):
			output = None
			try:
				output = subprocess.check_output(['ssh', '-A', '-t', qradarDeploymentConsole, 'ssh', '-A', '-t', host, 'systemctl', 'status', service], stderr=devNull, shell=False)
			except subprocess.CalledProcessError as e:
				output = e.output
		else:
			output = None
			try:
				output = subprocess.check_output(['ssh', '-A', '-t', qradarDeploymentConsole, 'ssh', '-A', '-t', host, 'service', service, 'status'], stderr=devNull, shell=False)
			except subprocess.CalledProcessError as e:
				output = e.output
		if 'running' in output:
			return True
	return False

# Check the appropriate servies status for all hosts in deployment
def checkServices():
	qradarDeploymentHosts = qradarDeploymentFetch()
	qradarDeploymentId = qradarDeploymentIdFetch()
	for host in qradarDeploymentHosts:
		hostName = host.attributes['hostName'].value
		applianceType = host.attributes['applianceType'].value
		if int(applianceType[:2]) in qradarApplianceTypeAllInOne:
			if host.attributes['console'].value == 'true':
				for service in servicesQRadarAll:
					if isServiceRunning(hostName, service) == True:
						logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 0)
					else:
						logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 1)
				for service in servicesQRadarConsole:
					if isServiceRunning(hostName, service) == True:
						logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 0)
					else:
						logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 1)
			else:
				for service in servicesQRadarAll:
					if isServiceRunning(hostName, service) == True:
						logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 0)
					else:
						logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 1)
				for service in servicesQRadarEventCollector:
					if isServiceRunning(hostName, service) == True:
						logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 0)
					else:
						logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 1)
				for service in servicesQRadarQFlowCollector:
					if isServiceRunning(hostName, service) == True:
						logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 0)
					else:
						logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 1)
		elif int(applianceType[:2]) in qradarApplianceTypeEventCollector:
			for service in servicesQRadarAll:
				if isServiceRunning(hostName, service) == True:
					logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 0)
				else:
					logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 1)
			for service in servicesQRadarEventCollector:
				if isServiceRunning(hostName, service) == True:
					logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 0)
				else:
					logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 1)
		elif int(applianceType[:2]) in qradarApplianceTypeQFlowCollector:
			for service in servicesQRadarAll:
				if isServiceRunning(hostName, service) == True:
					logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 0)
				else:
					logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 1)
			for service in servicesQRadarQFlowCollector:
				if isServiceRunning(hostName, service) == True:
					logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 0)
				else:
					logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 1)
		else:
			for service in servicesQRadarAll:
				if isServiceRunning(hostName, service) == True:
					logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 0)
				else:
					logMetric('ServiceStatus', qradarDeploymentId, hostName, service, 1)
	return 0

# Log Source statistics

def checkLogSourceStatistics():
	qradarDeploymentId = qradarDeploymentIdFetch()
	if isCurrentConsole() == True:
		qradarDeploymentHost = re.split('[- .]',socket.gethostname())[0]
		qradarConfDbConnection = psycopg2.connect(database='qradar', user='qradar')
		# All enabled Log Sources (Count)
		logSourceCount = qradarConfDbConnection.cursor()
		logSourceCount.execute("select count(distinct devicename) from sensordevice left outer join sensorprotocolconfig on sensorprotocolconfig.id=sensordevice.spconfig left outer join sensorprotocol on sensorprotocolconfig.spid=sensorprotocol.id where sensordevice.deviceenabled = 't';")
		logSourceCountValue = logSourceCount.fetchone()
		logMetric('LogSourceStatistics', qradarDeploymentId, qradarDeploymentHost, 'TotalCount', logSourceCountValue[0])
		# DNR Log Sources (Count)
		logSourceDNR = qradarConfDbConnection.cursor()
		logSourceDNR.execute("select count(distinct devicename) from sensordevice left outer join sensorprotocolconfig on sensorprotocolconfig.id=sensordevice.spconfig left outer join sensorprotocol on sensorprotocolconfig.spid=sensorprotocol.id where sensordevice.deviceenabled = 't' AND to_timestamp(sensordevice.timestamp_last_seen/1000) < (CURRENT_TIMESTAMP - 3 * interval '24 hours') AND NOT sensordevice.devicetypeid=246 AND NOT sensorprotocol.protocolname='WinCollect';")
		logSourceDNRValue = logSourceDNR.fetchone()
		logMetric('LogSourceStatisticsDNRSummary', qradarDeploymentId, qradarDeploymentHost, 'NotReporting', logSourceDNRValue[0])
		# DNR Windows Log Sources (Count)
		logSourceDNRWindows = qradarConfDbConnection.cursor()
		logSourceDNRWindows.execute("select count (distinct devicename) from sensordevice left outer join sensorprotocolconfig on sensorprotocolconfig.id=sensordevice.spconfig left outer join sensorprotocol on sensorprotocolconfig.spid=sensorprotocol.id where sensordevice.deviceenabled = 't' AND to_timestamp(sensordevice.timestamp_last_seen/1000) < (CURRENT_TIMESTAMP - 3 * interval '24 hours') AND NOT sensordevice.devicetypeid=246 AND sensorprotocol.protocolname='WinCollect';")
		logSourceDNRWindowsValue = logSourceDNRWindows.fetchone()
		logMetric('LogSourceStatisticsDNRSummary', qradarDeploymentId, qradarDeploymentHost, 'NotReportingWindows', logSourceDNRWindowsValue[0])
		# DNR WinCollects (Count)
		logSourceDNRWinCollect = qradarConfDbConnection.cursor()
		logSourceDNRWinCollect.execute("select count (distinct name) from ale_client where last_heartbeat < (CURRENT_TIMESTAMP - 3 * interval '24 hours')::timestamp AND deleted=false;")
		logSourceDNRWinCollectValue = logSourceDNRWinCollect.fetchone()
		logMetric('LogSourceStatisticsDNRSummary', qradarDeploymentId, qradarDeploymentHost, 'NotReportingWinCollect', logSourceDNRWinCollectValue[0])
		# Log Sources by Type (Count)
		logSourceByType = qradarConfDbConnection.cursor()
		logSourceByType.execute("select devicetypename,count(*) from sensordevice join sensordevicetype on sensordevice.devicetypeid=sensordevicetype.id where deviceenabled='t' and devicetypeid!='246' and devicename not like '%::%' and eccomponentid!='-1' group by devicetypename order by devicetypename asc;")
		rowCount = 0
		for row in logSourceByType:
			rowCount += 1
			logMetric('LogSourceStatisticsByType', qradarDeploymentId, qradarDeploymentHost, row[0], row[1])
		# DNR by Log Source Type (Count)
		logSourceDNRByType = qradarConfDbConnection.cursor()
		logSourceDNRByType.execute("select devicetypename,count(*) from sensordevice join sensordevicetype on sensordevice.devicetypeid=sensordevicetype.id where deviceenabled='t' and devicetypeid!='246' and devicename not like '%::%' and eccomponentid!='-1' and to_timestamp(timestamp_last_seen/1000) < (NOW() - 3* interval '24 hours') group by devicetypename order by devicetypename asc;")
		rowCount = 0
		for row in logSourceDNRByType:
			rowCount += 1
			logMetric('LogSourceStatisticsDNRByType', qradarDeploymentId, qradarDeploymentHost, row[0], row[1])
		qradarConfDbConnection.close()
	return 0

def checkOffenseStatistics():
	qradarDeploymentId = qradarDeploymentIdFetch()
	if isCurrentConsole() == True:
		qradarDeploymentHost = re.split('[- .]',socket.gethostname())[0]
		qradarConfDbConnection = psycopg2.connect(database='qradar', user='qradar')
		## Offense Statistics - Assigned by Username (Count)
		offenseStatisticsAssigned = qradarConfDbConnection.cursor()
		offenseStatisticsAssigned.execute("select distinct username, count(id) as assigned_offenses from offense_properties group by username order by username;")
		rowCount = 0
		for row in offenseStatisticsAssigned:
			if not row[0]:
				logMetric('OffenseStatisticsAssigned', qradarDeploymentId, qradarDeploymentHost, 'Not assigned', row[1])
			else:
				logMetric('OffenseStatisticsAssigned', qradarDeploymentId, qradarDeploymentHost, row[0], row[1])
		## Offense Statistics - Unassigned (Count)
		offenseStatisticsUnassigned = qradarConfDbConnection.cursor()
		# Unassigned - All
		offenseStatisticsUnassigned.execute("select count(*) from offense_view where offense_view.username='' and offense_view.closed_date IS null;")
		offenseStatisticsUnassignedAllValue = offenseStatisticsUnassigned.fetchone()
		logMetric('OffenseStatistics', qradarDeploymentId, qradarDeploymentHost, 'UnassignedAll', offenseStatisticsUnassignedAllValue[0])
		# Unassigned - Active
		offenseStatisticsUnassigned.execute("select count(*) from offense_view where offense_view.username='' and offense_view.end_time>(SELECT EXTRACT(EPOCH FROM now()- 11* INTERVAL '12 hours')*1000) and offense_view.closed_date IS null;")
		offenseStatisticsUnassignedActiveValue = offenseStatisticsUnassigned.fetchone()
		logMetric('OffenseStatistics', qradarDeploymentId, qradarDeploymentHost, 'UnassignedActive', offenseStatisticsUnassignedActiveValue[0])
		# Unassigned - All with Magnitude 4 or above
		offenseStatisticsUnassigned.execute("select count(*) from offense_view where offense_view.username='' and offense_view.magnitude>=4 and offense_view.closed_date IS null;")
		offenseStatisticsUnassignedAllAboveMag4Value = offenseStatisticsUnassigned.fetchone()
		logMetric('OffenseStatistics', qradarDeploymentId, qradarDeploymentHost, 'UnassignedAllAboveMag4', offenseStatisticsUnassignedAllAboveMag4Value[0])
		# Unassigned - Active with Magnitude 4 or above
		offenseStatisticsUnassigned.execute("select count(*) from offense_view where offense_view.username='' and offense_view.magnitude>=4 and offense_view.end_time>(SELECT EXTRACT(EPOCH FROM now()- 11* INTERVAL '12 hours')*1000) and offense_view.closed_date IS null;")
		offenseStatisticsUnassignedActiveAboveMag4Value = offenseStatisticsUnassigned.fetchone()
		logMetric('OffenseStatistics', qradarDeploymentId, qradarDeploymentHost, 'UnassignedActiveAboveMag4', offenseStatisticsUnassignedActiveAboveMag4Value[0])
		## Offense Statistics - Global (Count)
		offenseStatisticsCount = qradarConfDbConnection.cursor()
		# Created in last 24 Hours
		offenseStatisticsCount.execute("select count(*) from offense_view where offense_view.start_time> (SELECT EXTRACT(EPOCH FROM now()- 1* INTERVAL '24 hours')*1000) and offense_view.username='' and offense_view.closed_date IS null;")
		offenseStatisticsCount24Hours = offenseStatisticsCount.fetchone()
		logMetric('OffenseStatistics', qradarDeploymentId, qradarDeploymentHost, 'Count24Hours', offenseStatisticsCount24Hours[0])
		# Created in last 48 Hours
		offenseStatisticsCount.execute("select count(*) from offense_view where offense_view.start_time> (SELECT EXTRACT(EPOCH FROM now()- 1* INTERVAL '48 hours')*1000) and offense_view.username='' and offense_view.closed_date IS null;")
		offenseStatisticsCount48Hours = offenseStatisticsCount.fetchone()
		logMetric('OffenseStatistics', qradarDeploymentId, qradarDeploymentHost, 'Count48Hours', offenseStatisticsCount48Hours[0])
		# Created in last 72 Hours
		offenseStatisticsCount.execute("select count(*) from offense_view where offense_view.start_time> (SELECT EXTRACT(EPOCH FROM now()- 1* INTERVAL '72 hours')*1000) and offense_view.username='' and offense_view.closed_date IS null;")
		offenseStatisticsCount72Hours = offenseStatisticsCount.fetchone()
		logMetric('OffenseStatistics', qradarDeploymentId, qradarDeploymentHost, 'Count72Hours', offenseStatisticsCount72Hours[0])
		# Offense Statistics by Magnitude
		offenseStatisticsCount.execute("select magnitude,count(offense_view.magnitude) from offense_view where offense_view.closed_date IS null group by magnitude order by magnitude desc;")
		rowCount = 0
		for row in offenseStatisticsCount:
			logMetric('OffenseStatisticsByMagnitude', qradarDeploymentId, qradarDeploymentHost, row[0], row[1])
		qradarConfDbConnection.close()
	return 0

def checkRuleStatistics():
	qradarDeploymentId = qradarDeploymentIdFetch()
	if isCurrentConsole() == True:
		qradarDeploymentHost = re.split('[- .]',socket.gethostname())[0]
		qradarConfDbConnection = psycopg2.connect(database='qradar', user='qradar')
		# Rule Statistics - Total Count of Enabled
		ruleStatisticsCount = qradarConfDbConnection.cursor()
		ruleStatisticsCount.execute("select count (*) from custom_rule where cast (rule_data AS text) ~* '.*enabled=\"true\".*';")
		ruleStatisticsCountTotal = ruleStatisticsCount.fetchone()
		logMetric('RuleStatistics', qradarDeploymentId, qradarDeploymentHost, 'CountTotal', ruleStatisticsCountTotal[0])
		# Rule Statistics - Count of Rules Created Last Week
		ruleStatisticsCount = qradarConfDbConnection.cursor()
		ruleStatisticsCount.execute("select count(*) from custom_rule where create_date > (CURRENT_TIMESTAMP - 7* INTERVAL '24 hours')::timestamp with time zone AT TIME ZONE 'GMT';")
		ruleStatisticsCountCreatedLastWeek = ruleStatisticsCount.fetchone()
		logMetric('RuleStatistics', qradarDeploymentId, qradarDeploymentHost, 'CreatedLastWeek', ruleStatisticsCountCreatedLastWeek[0])
		# Rule Statistics - Count of Rules Modified Last Week
		ruleStatisticsCount = qradarConfDbConnection.cursor()
		ruleStatisticsCount.execute("select count(*) from custom_rule where mod_date > (CURRENT_TIMESTAMP - 7* INTERVAL '24 hours')::timestamp with time zone AT TIME ZONE 'GMT';")
		ruleStatisticsCountModifiedLastWeek = ruleStatisticsCount.fetchone()
		logMetric('RuleStatistics', qradarDeploymentId, qradarDeploymentHost, 'ModifiedLastWeek', ruleStatisticsCountModifiedLastWeek[0])
		qradarConfDbConnection.close()
	return 0	

def checkQRadarVersion():
	qradarDeploymentHosts = qradarDeploymentFetch()
	qradarDeploymentId = qradarDeploymentIdFetch()
	devNull = open(os.devnull)
	if isCurrentConsole() == True:
		for host in qradarDeploymentHosts:
			hostName = host.attributes['hostName'].value
			output = None
			try:
				output = subprocess.check_output(['ssh', hostName, '/opt/qradar/bin/myver'], stderr=devNull, shell=False).rstrip()
			except subprocess.CalledProcessError as e:
				output = e.output
			logMetric('QRadarVersion', qradarDeploymentId, hostName, 'CurrentVersion', output)
	else:
		for host in qradarDeploymentHosts:
			hostName = host.attributes['hostName'].value
			output = None
			try:
				output = subprocess.check_output(['ssh', '-A', '-t', qradarDeploymentConsole, 'ssh', '-A', '-t', hostName, '/opt/qradar/bin/myver'], stderr=devNull, shell=False).rstrip()
			except subprocess.CalledProcessError as e:
				output = e.output
			logMetric('QRadarVersion', qradarDeploymentId, hostName, 'CurrentVersion', output)
	return 0

def main():
	while True:
		isAlreadyRunning()
		checkServices()
		checkLogSourceStatistics()
		checkOffenseStatistics()
		checkRuleStatistics()
		checkQRadarVersion()
		time.sleep(pollingTime - time.time() % 60)

if __name__ == '__main__':
	main()
