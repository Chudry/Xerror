#!/usr/bin/env python

from __future__ import print_function
from openvas_lib import VulnscanManager, VulnscanException
from threading import Semaphore
from functools import partial
from xml.etree import ElementTree
import base64
import os,sys
import argparse
import json

import subprocess
import re
import time
import shlex

from channels import Group

from xerror.settings import BASE_DIR

from .models import Job


'''
Report formats 

5057e5cc-b825-11e4-9d0e-28d24461215b  Anonymous XML
910200ca-dc05-11e1-954f-406186ea4fc5  ARF
5ceff8ba-1f62-11e1-ab9f-406186ea4fc5  CPE
9087b18c-626c-11e3-8892-406186ea4fc5  CSV Hosts

c1645568-627a-11e3-a660-406186ea4fc5  CSV Results


6c248850-1f62-11e1-b082-406186ea4fc5  HTML
77bd6c4a-1f62-11e1-abf0-406186ea4fc5  ITG
a684c02c-b531-11e1-bdc2-406186ea4fc5  LaTeX
9ca6fe72-1f62-11e1-9e7c-406186ea4fc5  NBE
c402cc3e-b531-11e1-9163-406186ea4fc5  PDF
9e5e5deb-879e-4ecc-8be6-a71cd0875cdd  Topology SVG
a3810a62-1f62-11e1-9219-406186ea4fc5  TXT
c15ad349-bd8d-457a-880a-c7056532ee15  Verinice ISM
50c9950a-f326-11e4-800c-28d24461215b  Verinice ITG
a994b278-1f62-11e1-96ac-406186ea4fc5  XML


'''

opv_ip_addr = None 
opv_job_id  = None



def my_print_status(i):

	Group('pool').send({
                "text": json.dumps ({
                    "action": "openvas_running_status",
                    "job_id": opv_job_id,
                    "job_name": opv_ip_addr,
                    "job_openvas_current_status": str(i),
                    "job_openvas_log": "Running\n"
                })
            })
	print("[ openvas ] "+ str(i)),
	sys.stdout.flush()

def csv_reportwriting(report_id):

	print("[ openvas ] CSV Report Genertion started ")
	print("[ openvas ] Ip ")
	print (opv_ip_addr)
	print("[ openvas ] Host Scan ID ")
	print (opv_job_id)

	ip = opv_ip_addr
	idd = opv_job_id   
	# result_dir = BASE_DIR + '/reports/openvas/' +"opv_"+str(self.id)+"_"+ip
	result_dir = BASE_DIR + '/reports/openvas/' +"opv_"+str(idd)+"_"+ip
	# result_dir = os.path.dirname(os.path.abspath(__file__)) + "/results"
	format_id = 'c1645568-627a-11e3-a660-406186ea4fc5'
	
	if not os.path.exists(result_dir):
		os.makedirs(result_dir)
		print("[ openvas ] CSV Report path Generated ")
		print(result_dir)


	try:
		timestr = time.strftime("%Y%m%d")
		cmd = "omp --username admin --password admin -R %s -f %s " %(report_id, format_id)
		time.sleep(5)
		args = shlex.split(cmd)
		time.sleep(5)

		fout_path = result_dir + "/csv/"
		if not os.path.exists(fout_path):
			os.makedirs(fout_path)

		out = open(fout_path+opv_ip_addr+".csv", "w+")
		p = subprocess.Popen(args, stdout=out)
		time.sleep(5)
		out.close()
		print("[ openvas ] OMP CSV Report  Generated ")

	except Exception as e:
		print(e)
		print("[ openvas ] OMP CSV Report Generated got error  ")
		return
	print("[ openvas ] CSV Report Generated ")
	print("[ openvas ] Ending Report Generation Process ")
	# print(" finished ")


def write_report(manager, report_id, ip):

	idd = opv_job_id  
	# result_dir = BASE_DIR + '/reports/openvas/' +"opv_"+str(self.id)+"_"+ip
	result_dir = BASE_DIR + '/reports/openvas/' +"opv_"+str(idd)+"_"+ip


	print("[ openvas ] Report  Genertion Process started ")
	print("[ openvas ] Ip ")
	print (opv_ip_addr)
	print("[ openvas ] Host Scan ID ")
	print (opv_job_id)
	if not os.path.exists(result_dir):
		os.makedirs(result_dir)
		print("[ openvas ] Report Path Generated ")

	try:
		report = manager.get_report_xml(report_id)
	except Exception as e:
		print(e)
		print("[ openvas ] Xml Report Genertion Gor error ")
		return
	else:
		fout_path = result_dir + "/xml/"
		if not os.path.exists(fout_path):
			os.makedirs(fout_path)
			print("[ openvas ] Xml Report Generated ")
		
		fout = open(fout_path + ip + ".xml", "wb")
		fout.write(ElementTree.tostring(report, encoding='utf-8', method='xml'))
		fout.close()
		print("[ openvas ] Xml Report Generated to desti path  ")
		print(result_dir)

	try:
		report = manager.get_report_html(report_id)
	except Exception as e:
		print(e)
		return
	else:
		fout_path = result_dir + "/html/"
		if not os.path.exists(fout_path):
			os.makedirs(fout_path)

		html_text = report.find("report").text
		if not html_text:
			html_text = report.find("report").find("report_format").tail

		fout = open(fout_path + ip + ".html", "wb")
		fout.write(base64.b64decode(html_text))
		fout.close()

	print("[ openvas ] Html Report Generated ")


	csv_reportwriting(report_id)





def run(manager, ip):
	print("[ openvas ] Opv Running Status  ")
	Sem = Semaphore(0)
	scan_id, target_id = manager.launch_scan(
		target=ip,
		profile="Full and fast",
		callback_end=partial(lambda x: x.release(), Sem),
		callback_progress=my_print_status
	)
	Sem.acquire()
	report_id = manager.get_report_id(scan_id)
	print(target_id )
	print(scan_id )
	print(report_id)

	write_report(manager, report_id, ip)
	manager.delete_scan(scan_id)
	manager.delete_target(target_id)
	try:
		print("[ OPENVAS ] Opv Report creation checking ")
		opv_csv_file_name = BASE_DIR + '/reports/openvas/opv_'+str(opv_job_id)+"_"+str(ip)+"/csv/"+str(ip)+".csv"
		print(" [ OPENVAS ] Opv ip address found  ")
		with open(opv_csv_file_name) as f: 
			pass 

		print("[ OPENVAS ] Opv Report Creation checked ")
            
	except IOError:
		print("[ OPENVAS ] Opv Report not created, again starting process ")
		write_report(manager, report_id, ip)

        
            


def opv_scan_hacker( opv_id , opv_ip ):

# if __name__ == '__main__':
	# parser = argparse.ArgumentParser(description='Features Selection')
	# parser.add_argument('-u', '--user', required=True, help='OpenVas user')
	# parser.add_argument('-p', '--password', required=True, help='OpenVas password')
	# parser.add_argument('-i', '--ip', required=True, help='OpenVas ip host')
	# parser.add_argument('-t', '--target', required=True, help='Host target')

	# args = parser.parse_args()

	# if args.user:
	# 	admin_name = args.user
	# if args.user:
	# 	admin_password = args.password
	# if args.ip:
	# 	openvas_ip = args.ip
	# if args.target:
	# 	ip = args.target

	print("[ openvas ] Start opv Scanning  ")
	print("[ openvas ] Remote Host Ip address  "+opv_ip)

	global opv_job_id 
	global opv_ip_addr 
	
	opv_ip = opv_ip.encode('UTF8')

	opv_job_id 	= opv_id
	opv_ip_addr = opv_ip

	admin_name = "admin"
	admin_password = "admin"
	openvas_ip = "127.0.0.1"


	
	ip = opv_ip
	try:
		manager = VulnscanManager(openvas_ip, admin_name, admin_password)
		run(manager, ip  )
		print("[ openvas ] Ending opv Scanning  ")
		# return "success"

	except Exception as e:
		print("[ openvas ] connection error   ")
		print(e)
		# return "openvas connection error: " 
