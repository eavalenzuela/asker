# Meant as a counter for Red Teams running Responder without being careful
# Sends out LLMNR requests for random names and sends alerts if responded to.

import argparse, sys, time, socket, threading, struct, random, smtplib
from multiprocessing.pool import ThreadPool
from SocketServer import TCPServer, UDPServer, ThreadingMixIn
from subprocess import Popen, PIPE
from email.mime.text import *
from scapy.all import *

parser = argparse.ArgumentParser(description="Assorted protocol honeypot.")
parser.add_argument('namelist', help='File for the LLMNR sender server.')
parser.add_argument('-int' '--interface', dest='intface', help='Optional interface argument for listener.')
parser.add_argument('-e' '--email', dest='email_address', help='Email addresss to alerts when a response is detected.')
parser.add_argument('--smtp_server', dest='smtp_server', help='Address of your smtp server.')
parser.add_argument('--smtp_port', dest='smtp_port', help='Port for your smtp server.')
parser.add_argument('--smtp_username', dest='smtp_username', help='Username of your email account.')
parser.add_argument('--smtp_password', dest='smtp_password', help='Password of your email account.')
parser.add_argument('--randomize_src_ip', action='store_true', help='Make each LLMNR request appear to come from a differnt internal IP.')
args = parser.parse_args()

def sniff_worker(dst_port, query_name):
    response = sniff(filter="dst port "+str(dst_port), count=1, timeout=5)
    return response
    

class ThreadedServerUDP():
    def __init__(self, host, port, args):
        print('ThreadedServerUDP init')
        self.previous_email_sent_time = None
        self.host = host
        self.port = port
        self.email = None
        if args.intface:
            self.intface = args.intface
        else:
            self.intface = None
        self.filename = args.namelist
        if args.email_address:
            self.email = args.email_address

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
            query_name = get_name_to_send(self.filename).strip()
            print(query_name)
            print(query_name[len(query_name)-1])

            if query_name[len(query_name)-1] is not '.':
                print("query_name doesn't end in a period. appending...")
                query_name = query_name+'.'

            pool = ThreadPool(processes=1)
            result = pool.apply_async(sniff_worker, (15335, query_name))

            if self.intface is not None:
                (mac, ip) = getHwAddr(self.intface)
                if args.randomize_src_ip:
                    ip = get_random_ip()
                snd_pkt = Ether(src=mac, dst="01:00:5e:00:00:fc")/IP(dst="224.0.0.252", src=ip)/UDP(sport=15335, dport=5355)/LLMNRQuery(id=1337, qdcount=1, qd=DNSQR(qname=query_name.strip(), qtype=255))
            else:
                if args.randomize_src_ip:
                    ip = get_random_ip()
                    snd_pkt = Ether(dst="01:00:5e:00:00:fc")/IP(dst="224.0.0.252", ttl=1, src=ip)/UDP(sport=15335, dport=5355)/LLMNRQuery(id=1337, qdcount=1, qd=DNSQR(qname=query_name.strip(), qtype=255))
                else:
                    snd_pkt = Ether(dst="01:00:5e:00:00:fc")/IP(dst="224.0.0.252", ttl=1)/UDP(sport=15335, dport=5355)/LLMNRQuery(id=1337, qdcount=1, qd=DNSQR(qname=query_name.strip(), qtype=255))
            snd_pkt.show2()
            if self.intface is not None:
                print('sending request for '+query_name+' on interface: '+self.intface)
                sendp(snd_pkt, iface=self.intface)
            else:
                print('sending request for '+query_name+' on default interface')
                sendp(snd_pkt)

            bad_guy_response = result.get()

            if re.findall(r'^[a-zA-Z0-9]*\.', query_name)[0]:
                query_short_name = re.findall(r'^[a-zA-Z0-9]*\.', query_name)[0].replace('.', '')
                print('short name: '+query_short_name)
                for pkt in bad_guy_response:
                    if re.findall(query_short_name, str(pkt)):
                        print('FOUND MALICIOUS RESPONSE!')
                        if self.email:
                            print('Checking for alert times.')
                            if self.previous_email_sent_time is None:
                                print('No previous alerts sent. Sending...')
                                self.previous_email_sent_time = time.time()
                                send_alert_email(self.email, query_name, pkt, args)
                            elif (time.time() - self.previous_email_sent_time)>=600:
                                print('Previous alert sent '+(time.time()-self.previous_email_sent_time)+' seconds ago.')
                                self.previous_email_sent_time = time.time()
                                send_alert_email(self.email, query_name, pkt, args)
                            else:
                                print('Previous alert was sent less than 600 seconds ago. Holding...')
                        writeLogRaw("Malicious response from: "+pkt[IP].src)
                        print("Malicious response from: "+pkt[IP].src)

def send_alert_email(email, query_name, pkt, args):
    try:
        print('Preparing email...')
        email_body = "The Asker agent running on "+os.uname()[1]+" detected a response to a request it sent for "+query_name.strip()+".\nThe response originated from "+pkt[IP].src
        send_to = email
        sent_from = args.smtp_username
        subject = "Illegal LLMNR Response Detected"

        email_text = "\r\n".join([
            "From: "+os.uname()[1],
            "To: "+email,
            "Subject: Illegal LLMNR Response Detected",
            "",
            email_body])

        print("Message: "+email_text)
        print('Message prepared. Sending...')
        s = smtplib.SMTP(args.smtp_server, args.smtp_port)
        s.ehlo()
        s.starttls()
        s.ehlo()
        s.login(args.smtp_username, args.smtp_password)
        s.sendmail(args.smtp_username, email, email_text)
        s.close()
    except Exception as ex:
        print(ex)
    return

def get_name_to_send(namelist):
    names = []
    try:
        with open(namelist, 'rb') as infile:
            for line in infile:
                names.append(line)
    except Exception as ex:
        print(ex)
    if names:
        return (random.choice(names).strip())+'.'
    else:
        return 'adddc1-prod.'

def get_random_ip():
    ip_ranges = ['10.x.x.x', '172.16.x.x', '192.168.0.x']
    ip_range = random.choice(ip_ranges)
    final_ip = []
    for substring in ip_range.split('.'):
        if substring is 'x':
            r_octet = random.randint(2, 252)
            final_ip.append(str(r_octet))
        else:
            final_ip.append(str(substring))
    return '.'.join(final_ip)

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
        ThreadedServerUDP('224.0.0.252', 5355, args).listen()
        #ThreadedServerUDP("0.0.0.0", 5355).listen()
    except KeyboardInterrupt:
        print ('Exiting...')
        sys.exit()
    """
    except:
        print('Mainloop exception.')
        print(sys.exc_info()[0])
        print(sys.exc_info()[1])
        print(sys.exc_info()[2])
    """

if __name__ == '__main__':
    main()

