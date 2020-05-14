import json
import os 
import time

from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import get_object_or_404
from django.core.exceptions import ObjectDoesNotExist

from django.core.files.base import ContentFile
from django.shortcuts import redirect


from channels import Group

from xerror.settings import BASE_DIR
from .models import TextFile,Job,Config_exploit,Exploiated_system,Exploiated_system,MSF_rpc_connection,openvas_connection


from .tasks import process_file,process_ip_vul,process_nmap,process_exploitation,process_session_check,process_session_interact

from .nm_csv_parser import nmcsvpar
from mapper_cve_exploit import mapper_opn2msf_cve
from opv_csv_parser import openvas_csv_parse_detail
# from .msf_rpc_session_handler import session_interaction_handler

import time
from metasploit.msfrpc import MsfRpcClient





def index(request):
    '''
        INDEX check the rpc server connection 
        if it is already exists it redirect to dash board other then 
        to msf rpc login pate

    '''
    try:
        msf_credientials = MSF_rpc_connection.objects.get(pk=1)
        msf_pass = msf_credientials.rpc_pass
        msf_ip = msf_credientials.rpc_ip

        client = MsfRpcClient(msf_pass,server=msf_ip,ssl=False)
        print ("[ msf ] Rpc server not connected ")
    except Exception as e:
        return render(request, 'msf_login.html')

    else:
        job = Job.objects.all()
        print(" [ index ] project index \n\n\n\n ")
        return render(request, 'index.html',{"job":job })


# ++++++++++++++++++++++++++++++++++++ post exploit upload file/program handler function +++++++++++
def handle_file(file):
    """Get temporary uploaded file and write it into 'project/upload/' dir.

    Returns:
        tuple -- file path, file name
    """
    destination = BASE_DIR + '/upload/' + file.name
    with open(destination, 'wb+') as dest:
        for chunk in file.chunks():
            dest.write(chunk)
    return (destination, file.name)


@csrf_exempt
def upload(request):
    """Upload function.

    Take ajax request, handle file, save it to db,
    send websocket message to client for table change,
    then start 'process_file' celery task.

    Decorators:
        csrf_exempt

    Returns:
        json -- don't need it.
    """

    if request.is_ajax():
        data = {}
        destination, name = handle_file(request.FILES.values()[0])
        textfile = TextFile()
        textfile.name = name
        textfile.file = destination
        textfile.save()
        Group('pool').send({
            "text": json.dumps({
                "action": "uploaded",
                "file_id": request.FILES.keys()[0],
                "new_file_id": textfile.id,
            })
        })
        process_file.delay(textfile.id)
        data = {'msg': 'Success'}
    else:
        data = {'msg': 'Failed'}
    return JsonResponse(data)












@csrf_exempt
def msf_rpc_connect(request):

    if request.method == "POST":
        try:
            msf = MSF_rpc_connection.objects.get(pk=1)
            msf.rpc_uname  = request.POST['rpc_uname']
            msf.rpc_pass = request.POST['rpc_pass']
            msf.rpc_ip= request.POST['rpc_ip']
            msf.save()

        except Exception as e:
            print("[ MSF ] MSF exception ")
            msf = MSF_rpc_connection()
            msf.rpc_uname  = request.POST['rpc_uname']
            msf.rpc_pass = request.POST['rpc_pass']
            msf.rpc_ip= request.POST['rpc_ip']
            msf.save()
  
        print("[ MSF ] MSF credientials saved successfully ")
        # redire = nm_scan_index(request)
        # return redire
        return render(request, 'index.html')
    else:
        return render(request, 'msf_login.html')



@csrf_exempt    
def opv_rpc_connect(request):

    if request.method == "POST":
        try:
            opv = openvas_connection.objects.get(pk=1)
            opv.opv_uname  = request.POST['opv_uname']
            opv.opv_pass = request.POST['opv_pass']
            opv.opv_ip= request.POST['opv_ip']
            opv.save()

        except Exception as e:
            print("[ opv ] opv exception ")
            opv = openvas_connection()
            opv.opv_uname  = request.POST['opv_uname']
            opv.opv_pass = request.POST['opv_pass']
            opv.opv_ip= request.POST['opv_ip']
            opv.save()

        print("[ opv ] openvas credientials saved successfully ")
        redire = nm_scan_index(request)
        return redire
        # return render(request, 'nmap/nmap_scan2.html', {'files': files,"job":job })
    else:
        return render(request, 'msf_login.html')



# +++++++++++++++++++++++++++++++ Metasploit Post exploit halper functons ++++++++++++++++++++++

@csrf_exempt
def msf_session_intract_ajx(request):

    if request.is_ajax():
        data = {}

        print("\n\n\n\n ************************* Msf rhost shell command launcher ***************")
        form_data_collector = dict(request.POST)
        lst = form_data_collector["rhost_cmd"] 
        lst_session = form_data_collector["session_id"] 

        cmd = lst[0]
        cmd = cmd.encode("UTF8")

        session_id = lst_session[0]
        session_id = session_id.encode("UTF8")

        print "[+] Given Command to Execute : ",cmd
        print "[+] sesionid  ",session_id
        print type(cmd)
        print(form_data_collector)
        print(type(form_data_collector["rhost_cmd"]))
        process_session_interact.delay(session_id,cmd)


        Group('pool').send({
                "text": json.dumps({
                    "action":"session_interact_"+session_id, 
                    "session_interact_response": "\n\n Xerror :/~> "+cmd,
                    "check_status": "checking host up status so,keep patience ",
                })
            })
        data = {'msg': 'success '}
        return JsonResponse(data)




# interact index

def msf_session_intract(request,session_id,host_id,uuid):

    try:
        print "[ SESSION ]  shell interctation Starts "
        print session_id
        print host_id
        print uuid
        session_detail = Exploiated_system.objects.get(session_id=session_id,host_id=host_id,exploit_uuid=uuid)
        host_name = session_detail.host_name
        session_type = session_detail.session_type
        shell_tunnel = session_detail.tunnel_peer
        rport = session_detail.exploit_rport
        
        

        print "[ SESSION ] Interact: sesion object found  "

        resul_dict = {"rhost":host_name,"session_id":session_id ,"rport":rport,"session_type":session_type,"tunnel":shell_tunnel}
        return render(request, 'metasploit/sessions_handler.html', resul_dict)
    except Exception as e:
        print "[ SESSION ] Interact: sesion object not found 404 "
        ro = "object not found"
        return render(request, 'metasploit/sessions_handler.html', {"objerr":ro}  )



# session index 

def msf_session(request,id):
    """Index page view.
    id =rhost id
    Move all textfiles to context.
    """

    try:
        resul_dict = {}
        temp_dict = {}

        host_ipd = ''
        host_idd ='' 
        cve  = ""
        session = Exploiated_system.objects.filter(host_id=id)
        print "[ SESSION ] SESSION REQ  RENDERING  "
        for sesion_obj in session:
            temp_detail_dict ={}
            temp_detail_dict['host_id']          =  sesion_obj.host_id.encode("UTF8")
            temp_detail_dict['host_name']        =  sesion_obj.host_name.encode("UTF8")
            temp_detail_dict['rport']           =  sesion_obj.exploit_rport.encode("UTF8")
            temp_detail_dict['cve']             =  sesion_obj.cve_number.encode("UTF8")
            temp_detail_dict['exploit_name']     =  sesion_obj.exploit_name.encode("UTF8")
            temp_detail_dict['payload_name']     =  sesion_obj.payload_name.encode("UTF8")
            temp_detail_dict['exploited']       =  sesion_obj.exploited.encode("UTF8")
            temp_detail_dict['session_id']      =  sesion_obj.session_id.encode("UTF8")
            temp_detail_dict['exploit_uuid']     =  sesion_obj.exploit_uuid.encode("UTF8")
            temp_detail_dict['session_type']     =  sesion_obj.session_type.encode("UTF8")
            temp_detail_dict['tunnel_peer']     =  sesion_obj.tunnel_peer.encode("UTF8")
            temp_dict[sesion_obj.session_id.encode("UTF8")]  = temp_detail_dict
            
            host_ipd = sesion_obj.host_name.encode("UTF8")
            host_idd = sesion_obj.host_id.encode("UTF8")
            cve  =  sesion_obj.cve_number.encode("UTF8")




        # print temp_dict
        print host_idd
        print host_ipd
        temp_ = "none"
        if cve != '':
            temp_ = 'exist'


        resul_dict = {"ip_addr":host_ipd,"host_id": host_idd, "flag":temp_, "sessions":  temp_dict}
        return render(request, 'metasploit/sessions2.html', resul_dict)

    except Exception as e:
        ro = "object not sound"
        return render(request, 'metasploit/sessions2.html', {"objerr": ro})









@csrf_exempt
def msf_session_status_check_ajax(request):
    if request.is_ajax():
        print " [ SESSION ] SESSION STATUS CHEECK "

        session_data_collector = dict(request.POST)
        print type(session_data_collector)
        key= session_data_collector.keys()
        key= key[0].encode("UTF8")
        # This key dont have any value 
        id_lst = key.split("?")
        print id_lst

        session_id = id_lst[0]
        host_id    = id_lst[1]
        expl_uuid    = id_lst[2]

        print " [ SESSION ] sending SESSION STATUS CHEECK req to background process "
        process_session_check.delay(session_id,host_id,expl_uuid)
        print session_id
        print host_id
        print expl_uuid
        Group('pool').send({
                    "text": json.dumps({
                        "action": "session_status_checking",
                        "session_current_status":  "Xerror@W11 #:~> Checking sessoin",
                        "session_status":  "Checking",
                        "session_id": session_id,
                        
                           })
                       })

        data = {'msg': "Checking session  " }
        return JsonResponse(data)
    else:
        data = {'msg': 'Failed'}
        return JsonResponse(data)










# ******************************************* msf exploit index  ********************

def msf_exploit(request,id):

    print("\n\n\n\n [ Exploit ] MSF IP Exploit Result req recived ")
    try:
        job = Job.objects.get(pk=id)
        print(" [ Exploit ] MSF IP objec found  ")


        try:
            opv_csv_file_name = BASE_DIR + '/reports/openvas/opv_'+id+"_"+job.name+"/csv/"+job.name+".csv"
            ms_cve2exploit_File    = BASE_DIR+'/parsing/msf_module_result/msf_module_cve.txt' #metasploit db exploits and their cve number
            with open(opv_csv_file_name) as f:
                pass 
            # with open(ms_cve2exploit_File) as d:
            #     pass 

            print(" [ Exploit ] Starting Maping process")
            obj= mapper_opn2msf_cve(opv_csv_file_name,ms_cve2exploit_File) # cve2exploit mapper script in mapper_cve_exploit.py 
            mapping_dict =  obj.mapper()
            print "*"*65
            mapper_key_lst  =  mapping_dict.keys()

            resul_dict = {}
            host_ip    = ''
                                    
            for k in mapper_key_lst:
                if k == 'ip':
                    host_ip = mapping_dict[k]
                    print "ip address :" , k 
                else:
                    resul_dict[k] = mapping_dict[k]
                    print mapping_dict[k]
            print(" [ Exploit ] Maping process completed  ")

            print "*"*65
            files = TextFile.objects.all()
            job = Job.objects.all()

            mapped = { 'ip': host_ip, "cve_detail":resul_dict }
            resul = {'ip': host_ip,"id":id, 'mapped': resul_dict }

            print(" [ Exploit ] Rendering and sending result   ")
            # return render(request, 'metasploit/msf_exploit.html', resul)
            return render(request, 'metasploit/msf_exploit2.html', resul)

        except IOError,ObjectDoesNotExist :
            ro = 'file not found'
            print(" [ Exploit ] MSF IP Exploit Result file not Found 404  \n\n\n\n ")
            return render(request, 'metasploit/msf_exploit2.html', {'objerr':ro})
            # return render(request, 'metasploit/msf_exploit.html', {'ro':ro})
    except Exception as e:
        print(" [ Exploit ] Requested Object not Found 404  \n\n\n\n ")
        ro = 'Requested Object not found'
        return render(request, 'metasploit/msf_exploit2.html', {'objerr':ro})





#******************************************* Exploit  configuration sesion  ************************


def exploit_config(request,id):

    return render(request, 'metasploit/msf_exploit_config.html', {'ro':"sadfsad"})

def exploit_update(request):
    pass

def exploit_detail_extractor(exploit_name):

    try:
        print '[ MSFRPC ] ********************Exploit informaitn '
        exploit_name = exploit_name.replace(" ","")
        client = MsfRpcClient("123",server="127.0.0.1",ssl=False)
        # time.sleep(1)
        # exploit = client.modules.use('exploit', 'exploit/multi/samba/usermap_script')
        exploit = client.modules.use('exploit',exploit_name)
        # time.sleep(1)
        temp_dict ={} 
        temp_dict['archi']   = exploit.arch[0]
        temp_dict['authors'] =exploit.authors[0]
        temp_dict['desc']    =exploit.description
        temp_dict['isue_date']    =exploit.disclosuredate
        temp_dict['license']    =exploit.license
        temp_dict['payloads']    =exploit.payloads
        temp_dict['rank']    =exploit.rank
        temp_dict['type']    =exploit.type
        temp_dict['obj']    =exploit
        return  temp_dict
    except Exception as e:
        print"Msf rpc error "
        return "conneciton_sucks"



def exploit_form_data_extractor(form_data_collector):

        try:

            print '[ extract ] ********************Form Data Recived'
            temp_exploit_dict = {} 
            exploit_data= ''

            for k,v in  form_data_collector.items():
                exploit_data  = k.encode('UTF8')

            exploit_data = exploit_data.replace('[',"")
            exploit_data = exploit_data.replace(']',"")
            exploit_data = exploit_data.replace("'","")
            exploit_data_lst = exploit_data.split(",")
            #extract host db id and cve nimber  
            host_id = exploit_data_lst[0]
            host_id_extrat = host_id.split("?")
            host_id =host_id_extrat[0]
            cve_number = host_id_extrat[1]
            # print host_id
            # print cve_number
            # port      =exploit_data_lst[1]
            # proto     =exploit_data_lst[2]
            # severity  =exploit_data_lst[3]
            # exp_name  =exploit_data_lst[4]
            temp_exploit_dict['cve_number']  =cve_number
            temp_exploit_dict['host_id']  =host_id
            temp_exploit_dict['port']  =exploit_data_lst[1]
            temp_exploit_dict['port']  =exploit_data_lst[1]
            temp_exploit_dict['proto']  =exploit_data_lst[2]
            temp_exploit_dict['severity']  =exploit_data_lst[3]
            temp_exploit_dict['exp_name']  =exploit_data_lst[4]
            print temp_exploit_dict
            print '[ extract ] ********************Form Data Sended'

            return temp_exploit_dict

        except Exception as e:
            return "exploit_form_data_parser_sucks"





@csrf_exempt
def msf_exploit_config_ajx(request):
    if request.is_ajax():
        print "********************************************* config exploit ********************"

        form_data_collector = dict(request.POST)
        # data = exploit_form_data_extractor(form_data_collector)
        exploit_form_data  = exploit_form_data_extractor(form_data_collector)
        expl_name = exploit_form_data['exp_name']
        rport = exploit_form_data['port']
        
        

        exploit_detail_dict = exploit_detail_extractor(exploit_form_data['exp_name']) #extract selected exploitdata 
        exploit_cve_number  = exploit_form_data['cve_number']
        exploit_name        = exploit_form_data['exp_name']

        if exploit_detail_dict  != "conneciton_sucks":

            job          = Job.objects.get(pk=exploit_form_data["host_id"])
            rhost_ip      = job.name 
            rhost_ip       = rhost_ip.encode("UTF8")

            archi       =exploit_detail_dict['archi']   
            authors     =exploit_detail_dict['authors']  
            desc        =exploit_detail_dict['desc']    
            isue_date   =exploit_detail_dict['isue_date']    
            license     =exploit_detail_dict['license']    
            payloads    =exploit_detail_dict['payloads']    
            rank        =exploit_detail_dict['rank']    
            type_       =exploit_detail_dict['type']  

            exploit_obj =exploit_detail_dict['obj']  
            exploit_obj['RHOSTS'] = rhost_ip #"172.16.217.128"
            rhosts = exploit_obj['RHOSTS']

            #  save the exoloit configurations to config table
            '''
            job.exploit_config
                job exploit config will track each exploit 
                is configured or not ,, it saves cve to each exploit
                which is confiugred ... wit comma seperated string 

                first split exploit config based on comma and then checks if 
                requeseted string alreadted configured or not 
            '''
            expl_confi_lst = job.exploit_config
            expl_confi_lst = expl_confi_lst.split(",")
            '''
                i ip have many exploits and they are are stored in  exploitconfig column in comman seperated 
                form 
            '''

            if exploit_cve_number not in expl_confi_lst:
                config                       = Config_exploit()
                config.config_host_name      = rhost_ip
                config.config_host_id        = str(job.id)
                config.config_cve_number     = exploit_cve_number
                config.config_exploit_name   = exploit_name
                config.config_payload_name   = payloads[0]
                config.config_rhost          = rhosts
                config.config_rport          = rport  
                config.save()
                job.exploit_config = job.exploit_config + ","+exploit_cve_number
                job.save()


            Group('pool').send({
                    "text": json.dumps({
                        "action": "exploiting_config_exploit",
                        "msf_exploit_config_current_status":  "Config working",
                        "name":expl_name,
                        "archi":archi,
                        "authors":authors,
                        "desc":desc,
                        "rport":rport,
                        "license":license,
                        "rank":rank,
                        "type_":type_,
                        "rhosts": rhosts,
                           })
                       })



            for payl in payloads:
                print "payloads sending "
                Group('pool').send({
                        "text": json.dumps({
                            "action": "exploiting_config_exploit_payloads",
                            "payloads":payl,

                               })
                           })
            data = {'msg': job.exploit_config+"config Data Sended " }
            return JsonResponse(data)
        else:
            data = {'msg': "Msf Rpc connection not successfull  " }
            return JsonResponse(data)
    else:
        data = {'msg': 'Failed'}
        return JsonResponse(data)





#******************************************* Exploit rhost based on configured exploit  ************************

@csrf_exempt
def msf_exploit_vulnerability(request):
    if request.is_ajax():
        data = {}
        print("[ Exploit ] Exploiation Index Recived request to exploit ***************")
        form_data_collector = dict(request.POST)

        exploit_form_data = exploit_form_data_extractor(form_data_collector) #front request form data parser 
        exploit_cve_number  = exploit_form_data['cve_number']
        exploit_name        = exploit_form_data['exp_name']

        job            = Job.objects.get(pk=exploit_form_data["host_id"])
        exploit_lock   = job.exploit_lock
        host_id        = job.id
        expl_confi_lst = job.exploit_config

        expl_confi_lst = expl_confi_lst.split(",")
        print("[ Exploit ] Checking exploit Lock ")
        if exploit_lock == 'no': 
            print("[ Exploit ] Checking if exploit configured or not ")
            print exploit_lock

            if exploit_cve_number in expl_confi_lst:
                if exploit_form_data == "exploit_form_data_parser_sucks":
                    Group('pool').send({
                        "text": json.dumps({
                            "action": "exploiting_remort_host",
                            "msf_exploit_current_status":  "Exploit form data parsing Error ",
                            "job_status": "not running",
                               })
                           })
                    data = {'msg': "not Exploiteed exploit form data error  " }
                    return JsonResponse(data)
                else:
                    # here comes  the exploit baground process 
                    config_setting = Config_exploit.objects.get(config_exploit_name=exploit_name,  config_host_id=exploit_form_data["host_id"])
                    config_setting_id = str(config_setting.id)

                    print("[ Exploit ] All set handovering Exploitation process to background procss ")
                    process_exploitation.delay(config_setting_id,host_id)
                    job.exploit_lock = "acquired"
                    job.save()

                    Group('pool').send({
                        "text": json.dumps({
                            "action": "exploiting_remort_host",
                            "msf_exploit_current_status":  "Exploiation Process Started",
                            "job_status": "running",
                            "job_id": exploit_cve_number,
                               })
                           })
                    data = {'msg': str(config_setting.id)+"Yes config check and Exploiteed " }
                    return JsonResponse(data)
            else: 
                    data = {'msg': "Please config the Exploit first1 23   " }
                    return JsonResponse(data)
        else: 
                print("[ Exploit ] Exploit Lock  Acquried ")
                Group('pool').send({
                        "text": json.dumps({
                            "action": "exploiting_remort_host",
                            "msf_exploit_current_status":  "Already Exploiation Process Running Please till would ened",
                            "job_status": "running",
                            "job_id": exploit_cve_number,
                               })
                           })
                data = {'msg': "Exploit Lock  Acquried for requeseted CVE " }
                return JsonResponse(data)
    else:
        data = {'msg': 'Failed'}
        return JsonResponse(data)















# *************************************** Vulberability scanning halper functions  ************************************

def openvas_scan_index(request):
    print("\n\n\n\n [ OPENVAS ] Opv index Sending default Result req recived ")

    job = Job.objects.all()
    print(" [ OPENVAS ] Opv index Ended Sending Result \n\n\n\n ")
    # return render(request, 'openvas/openvas_scan.html', {"job":job })
    return render(request, 'openvas/openvas_scan2.html', {"job":job })



# raw html report path function 
def vulnerability_report(request,host_id):
    job  = Job.objects.get(pk=host_id)
    host_id = job.id
    ip= job.name

    result_dir =BASE_DIR + '/reports/openvas/' +"opv_"+str(host_id)+"_"+ip+"/html/"+ip+".html"
    desti  = BASE_DIR + '/templates/openvas/reports/generic_report.html' # raw html report viewer path 
    print result_dir


    with open(desti,"w") as repo:
        repo.write('<a href="{% url "parsing:openvas_scan_index"  %}"> back to Vul scaning </a>')
        with open(result_dir,"r") as f:
            for line in f:
                repo.write(line)
                # do whatever you want to

    return render(request, 'openvas/reports/generic_report.html')

# refined vulnerability report viewer 
def openvas_ip_detailed(request,id):
    
    try:
        print("\n\n\n\n [ OPENVAS ] Opv IP Detail Result req recived ")
        job = Job.objects.get(pk=id)
        opv_csv_file_name = BASE_DIR + '/reports/openvas/opv_'+id+"_"+job.name+"/csv/"+job.name+".csv"
        print(" [ OPENVAS ] Opv ip address found  ")
        try:
            with open(opv_csv_file_name) as f:
                pass 
            obj = openvas_csv_parse_detail(opv_csv_file_name) # vulnerability csv report  parser class in opv_csv_parser.py 
            print(" [ OPENVAS ] Opv IP Detail parsig \n\n\n\n ")
            resul_table,ip   = obj.opv_resul_table() 
            # return render(request, 'openvas/openvas_ip_detail.html', {'ro':resul_table,"ip_addr":ip, 'host_id': id.encode("UTF8")})
            return render(request, 'openvas/openvas_ip_detail2.html', {'ro':resul_table,"ip_addr":ip, 'host_id': id.encode("UTF8")})
        except IOError:
            ro = 'file not found'
            print(" [ OPENVAS ] Opv IP Detail Result file not Found 404  \n\n\n\n ")
            return render(request, 'openvas/openvas_ip_detail2.html', {'ro':ro})
    except Exception as e:
        ro = 'Requested Object not Found'
        print(" [ OPENVAS ] Requested IP Address dont have object, not Found 404  \n\n\n\n ")
        return render(request, 'openvas/openvas_ip_detail2.html', {'ro':ro})



     

    
@csrf_exempt
def openvas_scan_luncher(request):

    if request.is_ajax():
        data = {}

        print("\n\n\n\n ************************* Vulberability  Scan launcher ***************")
        form_data_collector = dict(request.POST)
        lst = form_data_collector["host_ip"] 

        ip_address_to_scan = lst[0]
        print type(ip_address_to_scan)
        ip_address_to_scan = ip_address_to_scan.encode('UTF8')
        print "[+] Given IP Address : ",ip_address_to_scan
        print type(ip_address_to_scan)
        print(form_data_collector)
        print(type(form_data_collector["host_ip"]))

        Group('pool').send({
                "text": json.dumps({
                    "action": "openvas_host_up_check",
                    "check_status": "openvas checking host up status so,keep patience ",
                })
            })

        host_up = True if os.system("ping -c 1 "+ip_address_to_scan) is 0 else False
        # time.sleep(5)
        if host_up:
  

            print len(form_data_collector)
            for i in form_data_collector:
                print i
                b = i.encode('UTF8')
                print "view"
                print type(b)
                print b
                print

            job = Job(
                name=ip_address_to_scan,
                status="started",
                vul_status="added"
            )
            job.save()

            # handover vulberatility process to task.py function
            process_ip_vul.delay(job.id,ip_address_to_scan)


            Group('pool').send({
            "text": json.dumps({
                "action": "openvas_taken_ip",
                "job_id": job.id,
                "job_name":  job.name,
                "job_status": job.status,
                   })
               })





            # print(type(request.POST))
            # print(request.POST)
            # ip = dict(request.POST)        
            # print ip
            # print type(ip)
            # for k,v in ip:
            #     print k
            #     print v
            # print ip.keys
            print (BASE_DIR + '/upload/' + "hellowwolrd.txt")
            print("************************* Openvas Scan launcher Ender Hand over to background process ***************\n\n\n\n")


            data = {'msg': ip_address_to_scan}
            data = {'msg': "ip adderss recived :: "+ip_address_to_scan}
        else:

            data = {'msg': "host is down "}
        # data = {'msg': }
    else:
        data = {'msg': 'Failed'}
    return JsonResponse(data)

















# *************************************** Simple Scanning halper functions  ************************************


def nm_scan_index(request):

    files = TextFile.objects.all()
    job = Job.objects.all()
    # return render(request, 'nmap/nmap_scan.html', {'files': files,"job":job })
    return render(request, 'nmap/nmap_scan2.html', {'files': files,"job":job })



def nm_ip_detailed(request,id):
    try:
        job = Job.objects.get(pk=id)
        csvname = "csv_"+id+"_"+job.name+".csv"
        filename = BASE_DIR + '/reports/' + csvname
        try:
            with open(filename) as f:
                pass 
            ro,host,os,ip_addr= nmcsvpar(filename) #csv parser funciton in nm_csv_parser.py
            return render(request, 'nmap/nmap_ip_detail2.html', {'ro':ro,"host":host,"os":os,"ip_addr":ip_addr,"host_id":id,"mac":"B0:4E:26:4D:40:28"})

        except IOError:
            print("[ Nmap ] File not accessible/ 404 not found  ")
            ro = 'file not found'
            return render(request, 'nmap/nmap_ip_detail2.html', {'ro':ro,"host_id":id })

    except Exception as e:
        print("[ Nmap ] Requested Object not foud ")
        ro = 'Requested Object not foud'
        return render(request, 'nmap/nmap_ip_detail2.html', {'ro':ro})



@csrf_exempt
def nm_scan_luncher(request):

    if request.is_ajax():
        data = {}

        print("\n\n\n\n ************************* Nmap Scan launcher ***************")
        form_data_collector = dict(request.POST)
        lst = form_data_collector["host_ip"] 
        ip_address_to_scan = lst[0]
        print "[+] Given IP Address : ",ip_address_to_scan
        print(form_data_collector)
        print(type(form_data_collector["host_ip"]))

        Group('pool').send({
                "text": json.dumps({
                    "action": "nm_host_up_check",
                    "check_status": "checking host up status so,keep patience ",
                })
            })

        host_up = True if os.system("ping -c 1 "+ip_address_to_scan) is 0 else False
        # time.sleep(5)
        if host_up:


            print len(form_data_collector)
            for i in form_data_collector:
                print i
                b = i.encode('UTF8')
                print type(b)
                print b
                print
            job = Job(
                name=ip_address_to_scan,
                status="started",
                nm_status="added"
            )
            job.save()

            # handover scanning process to backend celery server 
            process_nmap.delay(job.id,ip_address_to_scan)

            # process_ip_vul.delay(job.id,ip_address_to_scan)


            # process_vul_ip.delay(job.id,ip_address_to_scan)


            # print (BASE_DIR + '/upload/' + "hellowwolrd.txt")

            Group('pool').send({
            "text": json.dumps({
                "action": "taken_ip",
                "job_id": job.id,
                "job_name":  job.name,
                "job_status": job.status,
                   })
               })





            # print(type(request.POST))
            # print(request.POST)
            # ip = dict(request.POST)        
            # print ip
            # print type(ip)
            # for k,v in ip:
            #     print k
            #     print v
            # print ip.keys
            # print (BASE_DIR + '/upload/' + "hellowwolrd.txt")
            print("************************* Nmap Scan launcher Ender Hand over to background process ***************\n\n\n\n")


            data = {'msg': ip_address_to_scan}
            data = {'msg': "ip adderss recived :: "+ip_address_to_scan}
        else:

            data = {'msg': "host is down "}
        # data = {'msg': }
    else:
        data = {'msg': 'Failed'}
    return JsonResponse(data)






# *************************************** Start   ************************************
































