'''
For     :  Xerro Tech Sol's
web     :  0xError.com
project :  Xerror: An Autumated Pentest Tool
Authot  :  Ahsan ch 
on      :  30/11/2019 @10:11
contact : exploitmee@protonmail.com
'''


'''
Note Make sure that openvas installed and its been started 

'''
import subprocess
import re
import time
import os
import shlex

#change this to the IP address for a single host or whole class followed "/" e.g 192.168.0.1/24
ip_address = "127.0.0.1"
target_id = None
task_id   = None
report_id = None


# ------------------------- Scan type --------------------------------

# choose the only one appropiate scan type; just uncomment it 
#Use the configuration for the scan , the prefered on is full and fast
#config_id = "8715c877-47a0-438d-98a3-27c7a6ab2196"   #Discovery
#config_id = "085569ce-73ed-11df-83c3-002264764cea"  #empty
config_id = "daba56c8-73ec-11df-a475-002264764cea"  #Full and fast
#config_id = "698f691e-7489-11df-9d8c-002264764cea"  #Full and fast ultimate
#config_id = "708f25c4-7489-11df-8094-002264764cea"  #Full and very deep
#config_id = "74db13d6-7489-11d0f-91b9-002264764cea"  #Full and very deep ultimate
#config_id = "2d3f051c-55ba-11e3-bf43-406186ea4fc5"  #Host Discovery
# config_id = "bbca7412-a950-11e3-9109-406186ea4fc5"  #System Discovery



# ------------------------- Report Type -----------------------------------

# Html format for the report
format_id = "6c248850-1f62-11e1-b082-406186ea4fc5"
# xml format
#format_id = "a994b278-1f62-11e1-96ac-406186ea4fc5"



# -------------------------- connection ------------------------------------

# connect to openvas  and change password to admin
p = subprocess.Popen(["openvasmd", "--user=admin", "--new-password=admin"],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
output, err = p.communicate()

print("[+] end user creation ")


# ---------------------------- Target creation ------------------------------

cmd = ["omp", "--username", "admin", "--password", "admin",
 "--xml=<create_target><name>Subnet %s </name><hosts> %s </hosts></create_target>" %(ip_address, ip_address)]
p = subprocess.Popen(cmd,stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
output, err = p.communicate()
if "OK" in output:
    print "[+] target was created, target id:"
    target_id_tuple = re.findall(r'\w+(?:-\w+)+', output)
    target_id = target_id_tuple[0]
    print target_id


# ----------------------------- Task creation ------------------------------

cmd = ["omp", "--username", "admin", "--password", "admin","--xml=<create_task><name>My scan</name><comment>Deep scan on Subnet %s </comment><config id=\"%s\"/><target id=\"%s\"/></create_task>" %(ip_address, config_id, target_id)]
p = subprocess.Popen(cmd,stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
output, err = p.communicate()
if "OK" in output:
    print "[+] task was created, task id is:"
    task_id_tuple = re.findall(r'\w+(?:-\w+)+', output)
    task_id = task_id_tuple[0]
    print task_id
print "[+] end task id creation "


#Now that the task for the scan is ready start it
cmd = ["omp", "--username", "admin", "--password", "admin","--xml=<start_task task_id=\"%s\"/>" %task_id]
p = subprocess.Popen(cmd,stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
output, err = p.communicate()
if "OK" in output:
    print "[+] Task has started report id is:"
    report_id_tuple = re.findall(r'\w+(?:-\w+)+', output)
    report_id = report_id_tuple[0]
    print report_id
print "[+] end report id creation "


#wait for the scan to finish
while True:
    time.sleep(30)
    cmd = ["omp", "--username", "admin", "--password", "admin", "-G"]
    p = subprocess.Popen(cmd,stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False)
    output, err = p.communicate()
    if "Done" in output:
        time.sleep(15)
        print "[+] task finished"
        
        cmd = "omp --username admin --password admin -D %s  " % task_id 
        args = shlex.split(cmd)
        p = subprocess.Popen(args, stdout=subprocess.PIPE)

        cmd = "omp --username admin --password admin --xml='<delete_target target_id=\"%s\"/>'" % target_id
        args = shlex.split(cmd)
        p = subprocess.Popen(args, stdout=subprocess.PIPE)
        break
    else:
        print("[+] ---------Sbar rakh Shahzady -----------------")


# ---------------------------- Miscellaneous ----------------------------

time.sleep(5)
#use HTML format, grab the report and rename it with the current date
timestr = time.strftime("%Y%m%d")
cmd = "omp --username admin --password admin -R %s -f %s " %(report_id, format_id) 
time.sleep(5)
args = shlex.split(cmd)
time.sleep(5)
out = open("Report.html", "w+")
time.sleep(5)
p = subprocess.Popen(args, stdout=out)
time.sleep(5)
newname = 'Report_'+timestr+'.html' 
os.rename('Report.html', newname)


#--------------------------- out  put ------------------------
# out in html or xml based on sellection ... in cuttent directory 



