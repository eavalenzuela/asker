# Meant as a counter for Red Teams running Responder without being careful
# Sends out LLMNR requests for random names and sends alerts if responded to.

import argparse, sys, time, socket, threading, struct, random
from SocketServer import TCPServer, UDPServer, ThreadingMixIn
from subprocess import Popen, PIPE

try:
    from scapy.all import *
except NameError:
    pass

parser = argparse.ArgumentParser(description="Assorted protocol honeypot.")
parser.add_argument('namelist', type=argparse.FileType('r'), help='File for the LLMNR sender server.')
parser.add_argument('-int' '--interface', dest='intface', help='Optional interface argument for listener.')
args = parser.parse_args()

class ThreadedServerUDP():
    def __init__(self, host, port, intface):
        print('ThreadedServerUDP init')
        self.host = host
        self.port = port
        self.intface = intface

    def listen(self):
        print('TSU listen function')
        while True:
            rr = random.randrange(5, 25, 1)
            if self.intface is not None:
                p = sniff(filter="dst host 224.0.0.252", count=rr, iface=self.intface)
            else:
                p = sniff(filter="dst host 224.0.0.252", count=rr)
            print p.summary()
            print ('Building a packet to send!')
            #query_name = getNameToSend()
            if self.intface is not None:
                (mac, ip) = getHwAddr(self.intface)
                snd_pkt = Ether(src=mac, dst="01:00:5e:00:00:fc")/IP(dst="224.0.0.252", src=ip)/UDP(dport=5355)/LLMNRQuery(id=1337, qdcount=1, qd=DNSQR(qname="testing-ev.", qtype=255))
            else:
                snd_pkt = Ether(dst="01:00:5e:00:00:fc")/IP(dst="224.0.0.252", ttl=1)/UDP(dport=5355)/LLMNRQuery(id=1337, qdcount=1, qd=DNSQR(qname="testing-ev.", qtype=255))
            snd_pkt.show2()
            if self.intface is not None:
                print('sending on interface: '+self.intface)
                bad_guy_response = srp(snd_pkt, timeout=10)
            else:
                print('sending on default interface')
                bad_guy_response = srp(snd_pkt, timeout=10)
            print("response:")
            print(bad_guy_response)
            for i in bad_guy_response:
                print i
                writeLogRaw(i)

def get_port(service):
    while True:
        try:
            print (service + ':')
            port = int(raw_input('%s port: '))
        except TypeError:
            print('Error: invalid port specification.')
            continue
        else:
            if (port < 1) or (port > 65535):
                print('Error: invalid port number.')
                continue
            else:
                return port

def getHwAddr(ifname):
        print('getting HW id')
        if sys.platform == 'Windows':
            print('Windows detected... calling ipconfig.')
        elif sys.platform == 'linux2':
            print('Linux detected... calling ifconfig.')
            try:
                # Get MAC
                pArgs = ["ifconfig", ifname]
                pArgs2 = ['grep', '-o', '-E', '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}']
                p1 = Popen(pArgs, stdout=PIPE)
                p2 = Popen(pArgs2, stdin=p1.stdout, stdout=PIPE)
                (output, err) = p2.communicate()
                exit_code = p2.wait()
                mac = output
                
                # Get IP
                pArgs = ["ifconfig", ifname]
                pArgs2 = ['grep', '-o', '-E', "([0-9]{1,3}\.){3}[0-9]{1,3}"]
                p1 = Popen(pArgs, stdout=PIPE)
                p2 = Popen(pArgs2, stdin=p1.stdout, stdout=PIPE)
                (output, err) = p2.communicate()
                exit_code = p2.wait()
                print output.split('\n')[0]
                ip = output.split('\n')[0]
            except:
                print('Error executing ifconfig.')
        elif sys.platform == 'darwin':
            print('OS X detected... calling ifconfig.')
            try:
                # Get MAC
                pArgs = ["ifconfig", ifname]
                pArgs2 = ['grep', '-o', '-E', '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}']
                p1 = Popen(pArgs, stdout=PIPE)
                p2 = Popen(pArgs2, stdin=p1.stdout, stdout=PIPE)
                (output, err) = p2.communicate()
                exit_code = p2.wait()
                mac = output
                
                # Get IP
                pArgs = ["ifconfig", ifname]
                pArgs2 = ['grep', '-o', '-E', "([0-9]{1,3}\.){3}[0-9]{1,3}"]
                p1 = Popen(pArgs, stdout=PIPE)
                p2 = Popen(pArgs2, stdin=p1.stdout, stdout=PIPE)
                (output, err) = p2.communicate()
                exit_code = p2.wait()
                print output.split('\n')[0]
                ip = output.split('\n')[0]
            except:
                print(sys.exc_info())
        else:
            print('Platform could not be detected. Please rerun program without interface switch.')
            sys.exit(1)
        return mac, ip

def writeLogRaw(res):
    fopen = open('./asker.log', 'a')
    fopen.write(str(res))
    fopen.close()
    
def writeLog(client, data=''):
    separator = '='*50
    fopen = open('./asker.log', 'a')
    fopen.write('Time: %s\nIP: %s\nPort: %d\nData: %s\n%s\n\n' %(time.ctime(), client[0], client[1], data, separator))
    fopen.close()

def main():
    try:
        threads = []
        intface = None
        print args.intface
        if args.intface is not None:
            intface = args.intface
        ThreadedServerUDP('224.0.0.252', 5355, intface).listen()
        #ThreadedServerUDP("0.0.0.0", 5355).listen()
    except KeyboardInterrupt:
        print ('Exiting...')
        sys.exit()
    except:
        print(sys.exc_info()[0])
        print(sys.exc_info()[1])
        print(sys.exc_info()[2])

if __name__ == '__main__':
    main()

