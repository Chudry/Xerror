#!/usr/bin/env python
from __future__ import print_function

from openvas_lib import VulnscanManager, VulnscanException
from threading import Semaphore
from functools import partial
from xml.etree import ElementTree
import base64
import os,sys
import argparse


from xerror.settings import BASE_DIR
from .models import TextFile,Job




import subprocess
import re
import time
import os
import shlex

# '''
# Report formats 

# 5057e5cc-b825-11e4-9d0e-28d24461215b  Anonymous XML
# 910200ca-dc05-11e1-954f-406186ea4fc5  ARF
# 5ceff8ba-1f62-11e1-ab9f-406186ea4fc5  CPE
# 9087b18c-626c-11e3-8892-406186ea4fc5  CSV Hosts

# c1645568-627a-11e3-a660-406186ea4fc5  CSV Results


# 6c248850-1f62-11e1-b082-406186ea4fc5  HTML
# 77bd6c4a-1f62-11e1-abf0-406186ea4fc5  ITG
# a684c02c-b531-11e1-bdc2-406186ea4fc5  LaTeX
# 9ca6fe72-1f62-11e1-9e7c-406186ea4fc5  NBE
# c402cc3e-b531-11e1-9163-406186ea4fc5  PDF
# 9e5e5deb-879e-4ecc-8be6-a71cd0875cdd  Topology SVG
# a3810a62-1f62-11e1-9219-406186ea4fc5  TXT
# c15ad349-bd8d-457a-880a-c7056532ee15  Verinice ISM
# 50c9950a-f326-11e4-800c-28d24461215b  Verinice ITG
# a994b278-1f62-11e1-96ac-406186ea4fc5  XML



# '''



# def my_print_status(i):
# 	print(str(i)),
# 	sys.stdout.flush()

# def write_report(manager, report_id, ip):
# 	result_dir = os.path.dirname(os.path.abspath(__file__)) + "/results"
# 	if not os.path.exists(result_dir):
# 		os.makedirs(result_dir)

# 	try:
# 		report = manager.get_report_xml(report_id)
# 	except Exception as e:
# 		print(e)
# 		return
# 	else:
# 		fout_path = result_dir + "/xml/"
# 		if not os.path.exists(fout_path):
# 			os.makedirs(fout_path)
		
# 		fout = open(fout_path + ip + ".xml", "wb")
# 		fout.write(ElementTree.tostring(report, encoding='utf-8', method='xml'))
# 		fout.close()



# 	try:
# 		report = manager.get_report_html(report_id)
# 	except Exception as e:
# 		print(e)
# 		return
# 	else:
# 		fout_path = result_dir + "/html/"
# 		if not os.path.exists(fout_path):
# 			os.makedirs(fout_path)

# 		html_text = report.find("report").text
# 		if not html_text:
# 			html_text = report.find("report").find("report_format").tail

# 		fout = open(fout_path + ip + ".html", "wb")
# 		fout.write(base64.b64decode(html_text))
# 		fout.close()





# def run(manager, ip):
# 	# Sem = Semaphore(0)
# 	# scan_id, target_id = manager.launch_scan(
# 	# 	target=ip,
# 	# 	profile="Full and fast",
# 	# 	callback_end=partial(lambda x: x.release(), Sem),
# 	# 	callback_progress=my_print_status
# 	# )
# 	# Sem.acquire()

# 	scan_id
# 	report_id
# 	target_id

# 	report_id = manager.get_report_id(scan_id)
# 	print(target_id )
# 	print(scan_id )
# 	print(report_id)

# 	write_report(manager, report_id, ip)
# 	# manager.delete_scan(scan_id)
# 	# manager.delete_target(target_id)

# '''
# [2020-04-30 16:01:04,750: WARNING/Worker-3] dd7610ac-8642-435a-adcc-ecdba8f034bd
# [2020-04-30 16:01:04,750: WARNING/Worker-3] d7e17019-5f38-42b9-b488-139ea9bc1bfd
# [2020-04-30 16:01:04,751: WARNING/Worker-3] c8f7b11a-80ca-4800-80ec-f12fb57f312d


# '''
# # if __name__ == '__main__':

# def hacker():
# 	# parser = argparse.ArgumentParser(description='Features Selection')
# 	# parser.add_argument('-u', '--user', required=True, help='OpenVas user')
# 	# parser.add_argument('-p', '--password', required=True, help='OpenVas password')
# 	# parser.add_argument('-i', '--ip', required=True, help='OpenVas ip host')
# 	# parser.add_argument('-t', '--target', required=True, help='Host target')

# 	# args = parser.parse_args()

# 	# if args.user:
# 	# 	admin_name = args.user
# 	# if args.user:
# 	# 	admin_password = args.password
# 	# if args.ip:
# 	# 	openvas_ip = args.ip
# 	# if args.target:
# 	# 	ip = args.target

# 	admin_name = "admin"
# 	admin_password = "admin"
# 	openvas_ip = "127.0.0.1"
# 	ip = "192.168.0.103"


# 	try:
# 		manager = VulnscanManager(openvas_ip, admin_name, admin_password)
# 		run(manager, ip)
# 	except Exception as e:
# 			print(e)






# def run(report_id):


# 	format_id = 'c1645568-627a-11e3-a660-406186ea4fc5'
# 	timestr = time.strftime("%Y%m%d")
# 	cmd = "omp --username admin --password admin -R %s -f %s " %(report_id, format_id)
# 	time.sleep(5)
# 	args = shlex.split(cmd)
# 	time.sleep(5)
# 	out = open("Report.html", "w+")
# 	time.sleep(5)
# 	p = subprocess.Popen(args, stdout=out)
# 	time.sleep(5)
# 	newname = 'Report_'+timestr+'.html' 
# 	os.rename('Report.html', newname)
# 	print("finishe d")



# run('6bda7c99-d40b-4b43-a7ce-dae45b7b9b03')




def csv_reportwriting(report_id):


	result_dir = os.path.dirname(os.path.abspath(__file__)) + "/results"
	format_id = 'c1645568-627a-11e3-a660-406186ea4fc5'
	
	if not os.path.exists(result_dir):
		os.makedirs(result_dir)

	timestr = time.strftime("%Y%m%d")
	cmd = "omp --username admin --password admin -R %s -f %s " %(report_id, format_id)
	time.sleep(5)
	args = shlex.split(cmd)
	time.sleep(5)

	try:
		fout_path = result_dir + "/csv/"
		if not os.path.exists(fout_path):
			os.makedirs(fout_path)

		out = open(fout_path+report_id+".csv", "w+")
		p = subprocess.Popen(args, stdout=out)
		time.sleep(5)
		out.close()

	except Exception as e:
		print(e)
		return
	print("finished")
csv_reportwriting('6bda7c99-d40b-4b43-a7ce-dae45b7b9b03')
