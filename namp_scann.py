'''
for     :  Xerro Tech Sol's
web     :  0xError.com
project :  Xerror: An Autumated Pentest Tool
By      :  Ahsan ch 
on      :  11/28/2019 @5:15

'''

# pool distributes using a FIFO scheduling based nmap scannning running each host concurrently on each each process under pool limit 
import multiprocessing.pool 
import time
import os

number_of_processes=30 # taking max 30 process which can be inc or dec depend on CPU 
nmap_directory_name="nm2" #in current directry folder creation/replace/override etc
files = []
def runScan(target):
    print("Target scanning: "+target)
    # result = os.popen('nmap -Pn -T4 -sV -p- -oX '+nmap_directory_name+'/nmap-' + target + ".xml "+target).read().splitlines()
    # just to save time of scanning for demo work
    result = os.popen('nmap -Pn -T4 -sV -p- -oX '+nmap_directory_name+'/nmap-' + target + ".xml "+target).read().splitlines()
    time.sleep(3)
    os.popen('xsltproc '+nmap_directory_name+'/nmap-' + target +'.xml  -o '+nmap_directory_name+'/nmap-' + target +'.html' )
    time.sleep(2)
    # files[0]= nmap_directory_name+'/nmap-' + target +'.html'

 
 
if __name__ == "__main__":
    print(" ***** nmap multiprocess Scanner Started ***** ")
    if not os.path.exists(nmap_directory_name):
        os.makedirs(nmap_directory_name)

    # if we have bulk of ips in txt file 
    # input_file = open("input.txt", "r")
    # targets = input_file.readlines()
    # input_file.close()
    # targets = [x.strip() for x in targets]

    # demo for just 2 ips
    a= "192.168.0.1"
    # b= "192.168.0.105"
    targets = [a]

    if len(targets) < number_of_processes:
        number_of_processes = len(targets)

    index = 0
    processes = []
    for i in range(number_of_processes):
        processes.append(multiprocessing.Process(target=runScan,args=(targets[index],)))
        index+=1

    for p in processes:
        p.start()

    more_loop = True
    while more_loop:
        time.sleep(5)

        for i in range(0,number_of_processes) :
            if processes[i].is_alive():
                processes[i].join(1)
                print("jobs is not finished",processes[i])
            else:
                if index >= len(targets):
                    for p in processes:
                        p.join()
                    more_loop = False
                    break
                processes[i] = multiprocessing.Process(target=runScan,args=(targets[index],))
                processes[i].start()
                index+=1
   
    # os.popen('google-chrome '+ files[0]) #auto opens the chrome when its done 1 by one       
    print("Pool completed execution!!!")
    print("Exiting main thread.")
    exit(0)   


 #  at the end we just got xml file of each ip ....  seperately ... after wards we can convert it into CSV or html etc.
 # based on that scan we can run vulnerability scan  





 ########################## out put xml file ###################
 # in html format 
