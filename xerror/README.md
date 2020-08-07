
Ajax textfile load, parse(count symbols) with celery task, save result to db.  
Show progressing on each step. 
Accept only .txt files (optional).

Stack: Django, Channels, Celery, Jquery, websockets. 

```git clone https://github.com/freundallein/hicarser.git```  
```python manage.py migrate```  
```celery worker -A hicarser -l info```  
```python manage.py runserver```  
  or for productive capacity:  
start your wsgi webserver (gunicorn for example)  
```gunicorn hicarser.wsgi:application```  
start your asgi webserver (daphne for example)  
```daphne -b 0.0.0.0 -p 8001 hicarser.asgi:channel_layer```  
start asgi runworker  
```python manage.py runworker```  
edit your nginx config (hicarser.conf for example)  
Use for your profits.


Possible improvements:
- drag'n'drop file to upload  
- multiple files upload  
- config celery for several workers  
- draw file saving progress  
- alter client-side with React  
- for production use industrial database (MySQL, PostgreSQL)  
