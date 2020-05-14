import csv

def nmcsvpar(fname):
	file = fname
	ip   = ""
	ip_addr   = ""
	host   = ""
	os   = ""
	keys = ""
	os   = ""
	proto = []
	port  = []
	serv  = []
	serv_ver = []
	prod     = []
	resul = {}
	ser_fp =[]
	with open(file) as fh:
	    rd = csv.DictReader(fh, delimiter=',')
	    l = 0
	    for row in rd:
			# print(row)
			print
			if l == 0:
				keys= row.keys()
				os  = row["os"]
				ip_addr  = row["IP"]
				host  = row["Host"]
				l = 2
			
			if row['IP'] == ip_addr:
				proto.append(row['Proto'])
				port.append(row['Port'])
				serv.append(row['Service'])
				serv_ver.append(row['Service_version'])
				prod.append(row['Product'])
				ser_fp.append(row['Service FP'])

				# for k,v in row.items():
		# NSE Script ID		# 	print k,":",v
				# print("&********************")
	resul["host"] 	= host
	resul["os"]		 = os
	resul["proto"] 	 = proto
	resul["port"] 		= port
	resul["serv"] 		= serv
	resul["serv_ver"]  = serv_ver
	resul["prod"] 		= prod
	resul["ser_fp"] 		= ser_fp

	# print keys

	print host
	print os
	print ip_addr

	# print proto
	# print port
	# print serv
	# print serv_ver
	# print prod
	# print resul["port"][0]



# 	print(resul["host"])
	a = len(resul["proto"])
	l = 0
	row = ""
	for i in range(a):
		row = row+"<tr>"
		pro   = "<td>"+ resul["proto"][i]+"</td>"
		po   = "<td>"+ resul["port"][i]+"</td>"
		se   = "<td>"+ resul["serv"][i]+"</td>"
		se_v   = "<td>"+ resul["serv_ver"][i]+"</td>"
		prd   = "<td>"+ resul["prod"][i]+"</td>"
		# ser_fp   = "<td>"+ resul["ser_fp"][i]+"</td>"
		row = row+po+pro+se+se_v+prd+"</tr>"

		# print resul["proto"][0]
	print(row)


	return row,host,os,ip_addr

# s()

