import csv


class openvas_csv_parse_detail():

	def __init__(self,file):
		self.file = file

		self.CVE_dict = {}
		self.resul = {}
		self.openvas_csv_par()

# testing 

# /root/Videos/finlazation/xerror/reports/openvas/opv_078_192.168.0.104/csv/192.168.0.104.csv'
	# def __init__(self):
	# 	self.file = '/root/Videos/finlazation/xerror/reports/openvas/opv_41_172.16.217.128/csv/172.16.217.128.csv'

	# 	self.CVE_dict = {}
	# 	self.resul = {}
	# 	self.openvas_csv_par()

	def openvas_csv_par(self):
		'''
			structure is 
			result dict contain ip , host, ports( contais dict { port { port dict contais portdetaiil } })
			resul{ 
					port{
						port#{
							port detail{
		
							}//port detail 

						}//port#

					}//ports 


				}//resul dict

				e.g resul['ports']['80']['severity']


				2. csv_dict = contains dict of ip, port:CSV#
		'''

		with open(self.file) as fh:
		    rd = csv.DictReader(fh, delimiter=',')
		    l = 0;temp_port_dict = {}
		    for row in rd:
				if l == 0:
					# print (row.keys())
					ip_addr  = row["IP"]
					host  = row["Hostname"]
					self.resul['ip'] = ip_addr
					self.resul['host'] = host
					self.CVE_dict['ip_addr'] = ip_addr
					l = 2

				temp_port_detail_dict = {}

				if row['IP'] == ip_addr:

					port 			= row['Port']
					cvss 			= row['CVSS']
					proto 			= row['Port Protocol']
					sevrity 		= row['Severity']
					solution_type 	= row['Solution Type']
					nvt_name		= row['NVT Name']
					summary			= row['Summary']
					specfic_resul	= row['Specific Result']
					nvt_oid			= row['NVT OID']
					task_id			= row['Task ID']
					cve 			= row['CVEs']
					task_name		= row['Task Name']
					timestamp		= row['Timestamp']
					report_id		= row['Result ID']
					impact 			= row['Impact']
					solution		= row['Solution']
					affect_soft		= row['Affected Software/OS']
					vul_insight		= row['Vulnerability Insight']
					vul_dect_mtd	= row['Vulnerability Detection Method']
					prod_dect_resul = row['Product Detection Result']
					ref 			= row['Other References']
					
					if port :
						if sevrity != 'Log':
							temp_port_detail_dict['port'] = port
							temp_port_detail_dict['proto'] = proto
							temp_port_detail_dict['cvss'] = cvss
							temp_port_detail_dict['sevrity'] = sevrity
							temp_port_detail_dict['cve'] = cve 
							temp_port_detail_dict['nvt_name'] = nvt_name
							temp_port_detail_dict['impact'] = impact
							temp_port_detail_dict['summary'] = summary

							# print temp_port_detail_dict

							temp_port_dict[port] = temp_port_detail_dict
							if cve:
								if cve != 'NOCVE':
									self.CVE_dict[port] = cve

	        self.resul["ports"]  = temp_port_dict
			


		# print
		# # print ip_addr
		# print self.resul
		# # print resul.keys()
		# print
		# # print self.resul['ip']
		# print self.resul['ports']['110']['port']

		# print self.CVE_dict


	def openvas_cve_dict(self):
		'''
			structure is 
			result dict contain ip , host, ports( contais dict { port { port dict contais portdetaiil } })
			resul{ 
					port{
						port#{
							port detail{
		
							}//port detail 

						}//port#

					}//ports 


				}//resul dict

				e.g resul['ports']['80']['severity']
		'''

		return self.CVE_dict



	def openvas_result_dict(self):
		'''
			structure is 
			result dict contain ip , host, ports( contais dict { port { port dict contais portdetaiil } })
			resul{ 
					port{
						port#{
							port detail{
		
							}//port detail 

						}//port#

					}//ports 


				}//resul dict

				e.g resul['ports']['80']['severity']
		'''

		return self.resul
	

	def opv_resul_table(self):
		row = ''
		for  k,v in self.resul["ports"].items():

			# test purpose we can dynamically pring but not append in table in  order .... 

			# print("******************************")
			# temp =self.resul["ports"][k].items()
			# for l,m in temp:
			# 	print l,"=>",m

			tr = '<tr>'
			td = tr+"<td>"+self.resul["ports"][k]['port']+"</td>"
			td = td+"<td>"+self.resul["ports"][k]['proto']+"</td>"
			td = td+"<td>"+self.resul["ports"][k]['cvss']+"</td>"
			td = td+"<td>"+self.resul["ports"][k]['cve']+"</td>"
			td = td+"<td>"+self.resul["ports"][k]['sevrity']+"</td>"
			td = td+"<td>"+self.resul["ports"][k]['nvt_name']+"</td>"
			td = td+"<td>"+self.resul["ports"][k]['impact']+"</td>"
			td = td+"<td>"+self.resul["ports"][k]['summary']+"</td>"

			tr = td+"</tr>"
			row = row+tr
			# print tr
		return row,self.resul['ip']



# # a = openvas_csv_parse_detail('/root/Desktop/celery_setup.txt/dj_file_upload/hicarser/reports/openvas/opv_176_192.168.0.78/csv/192.168.0.78.csv')
# a = openvas_csv_parse_detail()
# # resul =  a.openvas_result_dict()
# a.opv_table()
