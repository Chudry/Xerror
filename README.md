# Xerror


Xerror is an automated penetration tool , which will helps security professionals and non professionals to automate their pentesting tasks. Xerror will do all tests and, at the end generate two reports for executives and analysts.

After completion of Xerror, it will will provides GUI and internally it supports openVas, nessus and nexpose for vulnerability scanning, Metasploit for exploitation and gives GUI based options after successful exploitation e.g Meterpreter sessoins.
Building in python as major. 


How to use this porject: 
 1.Activate virtual enviroment by following command 
      souce env/bin/activate
 2. Start redis server
      service redis-server start
 3. start python srver 
      1. cd xerror 
      2. python mana.py runserver 
 4. start celery server 
      1. cd xerror 
      2. celery -A xerror worker -l info 
 5. start msfrpc server 
      msfrpcd -P 123 -S -a 127.0.0.1
 6. start openvas server for default set OMP server credientials to admin@admin 127.0.0.1 9392 
 
 
 You are goog to go 
 
 This is xerror Beta version, soon complete version will be uploaded with complete explanation and detail of each step ...   
 
 
 
 
 
 
