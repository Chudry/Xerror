from __future__ import absolute_import
import datetime
import json
import os,sys
import time
import subprocess

from subprocess import Popen, PIPE
from shlex import split

from channels import Group
 
from xerror.celery import app
from .models import TextFile,Config_exploit,Exploiated_system


from xerror.settings import BASE_DIR
from .models import TextFile,Job


from .openvas_scanner_script import opv_scan_hacker 
from .nm_xml_parser import nmxmlparser
from .msf_rpc_handler import MSF_rpc_Hhandler


from metasploit.msfrpc import MsfRpcClient





@app.task
def process_file(file_id):


    file = TextFile.objects.get(pk=file_id)
    with open(file.file) as f:
        size = os.fstat(f.fileno()).st_size
        if size == 0:
            result = 0
            Group('pool').send({
                "text": json.dumps({
                    "action": "processing",
                    "file_id": file_id,
                    "progress": 100,
                })
            })
        else:
            step = size // 100
            result = 0
            for line in f:
                for char in line:
                    result += 1
                    if result % step == 0:
                        Group('pool').send({
                            "text": json.dumps({
                                "action": "processing",
                                "file_id": file_id,
                                "progress": result // step,
                            })
                        })

    file.amount = result
    file.completed = datetime.datetime.now()
    file.save()
    for i in range(1,10):
        time.sleep(2)
        Group('pool').send({
                            "text": json.dumps({
                                "action": "processing",
                                "file_id": file_id,
                                "progress": str(i),
                            })
                        })

    Group('pool').send({
        "text": json.dumps({
            "action": "completed",
            "file_id": file_id,
            "file_amount": result,
        })
    })
















# *********************************************************  Vuonerability Scanning ************************************

@app.task
def process_ip_vul(job_id,ip_addr):

    job = Job.objects.get(pk=job_id)
    print("[ openvas ] Start Background Process ")
    opv_scan_hacker(job_id,ip_addr)
 
    # else:    
    if True:
        job.status ="completed"
        job.vul_status = "OpenVass Vul scan completed "
        job.save()

        Group('pool').send({
                "text": json.dumps ({
                    "action": "completed_ip",
                    "job_id": job_id,
                    "job_name": job.name,
                    "job_status": job.status,
                })
            })   


    print("[ openvas ] Ending opv Background Process ")











# *********************************************************  Generabl Scanning ************************************




@app.task
def process_nmap(job_id,ip_addr):

    job = Job.objects.get(pk=job_id)

    def run(command):
        process = Popen(command, stdout=PIPE, shell=True)
        while True:
            line = process.stdout.readline().rstrip()
            if not line:
                break
            yield line


    name_xml = "nm_"+str(job_id)+"_"+str(job.name)+".xml"
    scnRepo = BASE_DIR + '/reports/' + name_xml
    print("[ NMAP  ] ************************* Nmap Background Process running **************")
    print scnRepo

    for path in run("nmap -T4 -O -sV --stats-every .01 "+ip_addr+" -oX "+scnRepo):
            Group('pool').send({
                "text": json.dumps ({
                    "action": "not_completed",
                    "job_id": job_id,
                    "job_name": job.name,
                    "job_nmap_status": str(path),
                    "job_current_status": "Running",
                    # "job_status": "Running",
                })
            })
            print "[ NMAP ] "+path


    print("[NMAP ]  converting csv file  ")
    name_csv = "csv_"+str(job_id)+"_"+str(job.name)+".csv"    
    print "[ NMAP ]  "+nmxmlparser(name_xml,name_csv)
    print "[ NMAP ]  finshed Nmpa scanning "

    # for i in range(1,10):
    #     print(i)
    #     time.sleep(2)

    job.status ="completed"
    job.nm_status="Nmap_scan_completed"

    job.save()

    Group('pool').send({
            "text": json.dumps ({
                "action": "completed_ip",
                "job_id": job_id,
                "job_name": job.name,
                "job_status": job.status,
            })
        })    
    print("[ NMAP  ]  ************************* Nmap Background Process Ended  **************")







# *********************************************************  Metasploit exploit and post exploits( totally depend on external scripts ) ************************************

@app.task
def process_exploitation(config_id,job_id):
    print("[ Exploit ] ************************ [ Exploit] Starting Background Process ******************************")
    # Job.objects.get(pk=exploit_form_data["host_id"])
    obj = MSF_rpc_Hhandler()
    obj.try_exploit(config_id,job_id)

    print("[ Exploit ] ************************ [ Exploit] Background Process Ended  ******************************")





@app.task
def process_session_check(session_id,host_id,uuid):
    print(" [ SESSION ] Backend session check  process STARTED ")
    try:
        client = MsfRpcClient("123",server="127.0.0.1",ssl=False)
        print ("[ SESSION ] Rpc server connected ")
    except Exception as e:
            Group('pool').send({
                    "text": json.dumps({
                        "action": "session_status_checking",
                        "session_current_status":   "\n xerror@w11:~> Metasploit Connection Not succesfuull \n",
                        "session_status":  "Msf conect/error",
                        "session_id": session_id,
                        
                           })
                       })
    else:
        print ("[ SESSION ] Checking session status  ")
        session_idd = client.sessions.list 
        lst = session_idd.keys()
        session_id = int(session_id)
        if session_id in lst:
            print ("[ SESSION ] Session Active for following uuid ")
            print (uuid)

            Group('pool').send({
                    "text": json.dumps({
                        "action": "session_status_checking",
                        "session_current_status":   "\n xerror@w11:~> Metasploit Sssion to Remote host is active \n",
                        "session_status":  "active",
                        "session_id": session_id,
                        
                           })
                       })
        else:
            print ("[ SESSION ] Session is not active for following uuid ")
            print (uuid)
            Group('pool').send({
                    "text": json.dumps({
                        "action": "session_status_checking",
                        "session_current_status":   "\n xerror@w11:~> Metasploit Session to Remote host is not active \n",
                        "session_status":  "no",
                        "session_id": session_id,
                        
                           })
                       })




@app.task
def process_session_interact(session_id,cmd):

    print("*****************************backend session check  process")
    try:
        client = MsfRpcClient("123",server="127.0.0.1",ssl=False)
        print ("********************** rpc connected ")
    except Exception as e:
            Group('pool').send({
                "text": json.dumps({
                    "action":"session_interact_"+session_id, 
                    "session_interact_response": "\n Metasploit connection Error, ",
                })
            })
    else:
        session_idd     =   client.sessions.list.keys()
        session_id = int(session_id)

        if session_id in session_idd:
            
            Group('pool').send({
                "text": json.dumps({
                    "action":"session_interact_"+str(session_id), 
                    "session_interact_response": "\n Rhost Session found Executing command \n",
                })
            })

            try:
                print "*********************** shell command"
                print cmd
                cmd = cmd.encode("UTF8")
                shell = client.sessions.session(session_id) 
                shell.write(cmd+'\n')
                time.sleep(3)
                resul = shell.read()
                print resul
                if resul:
                    Group('pool').send({
                        "text": json.dumps({
                        "action":"session_interact_"+str(session_id), 
                        "session_interact_response": "\n "+resul,
                    })
                    })
                else:
                    print "no response"
                    Group('pool').send({
                        "text": json.dumps({
                        "action":"session_interact_"+str(session_id), 
                        "session_interact_response": "No output from from remote shell to given command\n ",
                    })
                    })
            except Exception as e:
                print e
                Group('pool').send({
                    "text": json.dumps({
                    "action":"session_interact_"+str(session_id), 
                    "session_interact_response": "\n Shell command executing in remote host got error  ",
                })
            })




        else:
            Group('pool').send({
                "text": json.dumps({
                    "action":"session_interact_"+str(session_id,) ,
                    "session_interact_response": "\n Rpc session Expired or Sesion not found  ",
                })
            })



