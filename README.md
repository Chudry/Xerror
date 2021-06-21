# Xerror


Xerror is an automated penetration tool , which will help security professionals and non professionals to automate their pentesting tasks. Xerror will perform all tests and, at the end generate two reports for executives and analysts.

Xerror provides GUI easy to use menu driven options.Iinternally it supports openVas for vulnerability scanning, Metasploit for exploitation and gives GUI based options after successful exploitation e.g Meterpreter sessoins.
Building in python as major. 

Xerror build on python2 as a primary language and Django2 as web framework along with, websockets(django channel) on celery server and Redis srver to achieve asynchronization. On front side it supports Djanog default template enging language which is jinga2 and jquery.   


How to use this porject: </br>
1. Activate virtual enviroment by using following command( make sure you have pre-installed py virtual env) 
```
      souce env/bin/activate
```
2. Start redis server</br>
```
      service redis-server start
```
3. start python srver </br>
```
      cd xerror 
```
```
      python manage.py runserver 
```
4. start celery server( run this in new terminal) </br>
```
      cd xerror 
```
```
     celery -A xerror worker -l info 
```
5. start msfrpc server for metasploit </br>
```
     msfrpcd -P 123 -S -a 127.0.0.1</br>
```
6. start openvas server and set OMP server credientials to ```admin@admin``` 127.0.0.1 9392 </br>
 
 
 You are good to go </br>
 
 This is xerror Beta version, soon complete version will be uploaded with complete explanation and detail of each step ...   </br>
 
 ![alt text](https://i.imgur.com/oJQH6ax.png)
 
 
![alt text](https://i.imgur.com/RTyPiiZ.png)

![alt text](https://i.imgur.com/yLMMNC2.png)


![alt text](https://i.imgur.com/K7k2uRu.png)

![alt text](https://i.imgur.com/dnDWm0O.png)

![alt text](https://i.imgur.com/pn0evVH.png)




![alt text](https://i.imgur.com/tMo0B5S.png)

![alt text](https://i.imgur.com/65JUi9y.png)
 
 ![alt text](https://i.imgur.com/BIqlXr9.png)
 
 
 ![alt text](https://i.imgur.com/dV3NuRv.png)
 
 ![alt text](https://i.imgur.com/W9bBejm.png)
 
 
 
 
 
 
 
 
</br>

<b>Contact :</b> exploitmee@protonmail.com 
