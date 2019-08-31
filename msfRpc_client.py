


#!/usr/bin/env python
# MSF-RPC - A  Python library to facilitate MSG-RPC communication with Metasploit
# Chudry  - ecploitmee@protonmail.com
# This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
# You should have received a copy of the GNU General Public License along with this program. If not, see <http://www.gnu.org/licenses/>.

import msgpack
import httplib

class Msfrpc:
  class MsfError(Exception):
    def __init__(self,msg):
      self.msg = msg
    def __str__(self):
      return repr(self.msg)

  class MsfAuthError(MsfError):
    def __init__(self,msg):
      self.msg = msg
    
  def __init__(self,opts=[]):
    self.host = opts.get('host') or "127.0.0.1"
    self.port = opts.get('port') or 55552
    self.uri = opts.get('uri') or "/api/"
    self.ssl = opts.get('ssl') or False
    self.authenticated = False
    self.token = False
    self.headers = {"Content-type" : "binary/message-pack" }
    if self.ssl:
      self.client = httplib.HTTPSConnection(self.host,self.port)
    else:
      self.client = httplib.HTTPConnection(self.host,self.port)
 
  def encode(self,data):
    return msgpack.packb(data)
  def decode(self,data):
    return msgpack.unpackb(data)

  def call(self,meth,opts = []):
    if meth != "auth.login":
      if not self.authenticated:
        raise self.MsfAuthError("MsfRPC: Not Authenticated")

    if meth != "auth.login":
      opts.insert(0,self.token)

    opts.insert(0,meth)
    params = self.encode(opts)
    self.client.request("POST",self.uri,params,self.headers)
    resp = self.client.getresponse()
    return self.decode(resp.read()) 
  
  def login(self,user,password):
    ret = self.call('auth.login',[user,password])
    if ret.get('result') == 'success':
        
        self.authenticated = True
        self.token = ret.get('token')

        print "\n[*] login :"+ret.get('result')
        print "[*] Host  :  "+ self.host 
        print "[*] Port  :  "+ str(self.port )
        print "[*] uri   : "+ self.uri 
        print "[*] ssl   : "+ str(self.ssl) 
        print "[*] token :"+ str(self.token) 

        #second toke for two sessions 
        # ret2 = self.call('auth.login',[user,password])
        # token2 = ret2.get('token')
        # print "[*] token2 :"+str(token2)


        print

        return True
    #in case wrong username or password
    else:
        print "not "
        login_result = self.MsfAuthError("MsfRPC: Authentication failed")
        print "[*] Login : " + str(login_result)
        print "[*] exit the script "
        exit()
        # print "not loging"

if __name__ == '__main__':
  
  # Create a new instance of the Msfrpc client with the default options
  client = Msfrpc({})

  # Login to the msfmsg server using the password "abc123"
  client.login('msf','jLqRITPw')


  # Get a list of the exploits from the server
  mod = client.call('module.exploits')

#getting all keys from mod 
  keys = mod.keys()  

  #looping each exploit with its compatible payloads
  for k in keys:
      l = len(mod[k])

      for v in range(l):
        print "Compatible payloads for : %s\n" % mod[k][v]
        ret = client.call('module.compatible_payloads',[mod[k][v]])
        for i in (ret.get('payloads')):
          print "\t%s" % i



  # listing each module with its payloads 
  # Grab the first item from the modules value of the returned dict
  # print "Compatible payloads for : %s\n" % mod['modules'][5]
  
  # # Get the list of compatible payloads for the first option
  # ret = client.call('module.compatible_payloads',[mod['modules'][5]])
  # for i in (ret.get('payloads')):
  #   print "\t%s" % i
