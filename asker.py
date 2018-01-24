# Meant as a counter for Red Teams running Responder without being careful
# Sends out LLMNR requests for random names and sends alerts if responded to.

import argparse, sys, time, ssl, socket, threading, struct
from SocketServer import TCPServer, UDPServer, ThreadingMixIn

parser = argparse.ArgumentParser(description="Assorted protocol honeypot.")
parser.add_argument('--ssh', action='store_true', help='Runs an ssh honeypot.')
parser.add_argument('--llmnr', action='store_true', required='--llmnr-name-list' in sys.argv, help='Runs the LLMNR sender server, to fish for Responder sessions. Requires a file with names of servers to query for. These should be slight variations on server names in your environment.')
parser.add_argument('--llmnr-name-list', required='--llmnr' in sys.argv, type=argparse.FileType('r'), dest='llmnrnames', help='File for the LLMNR sender server.')
args = parser.parse_args()

class ThreadedServerUDP():
    def __init__(self, host, port):
        print('ThreadedServerUDP init')
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print('pre-bind: %s, %d' %(self.host, self.port))
        self.sock.bind(('', self.port))
        mreq = struct.pack("4sl", socket.inet_aton(host), socket.INADDR_ANY)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    def listen(self):
        print('TSU listen function')
        while True:
            #threading.Thread(target = self.listenToClient, args = (self.host, self.port))
            data = self.sock.recv(1024)
            print data

    def listenToClient(self, sock, port):
        print('TSU listenToClient function')
        size = 1024
        while True:
            try:
                data = self.sock.recv(size)
                if data:
                    self.sock.sendto(data ('224.0.0.252', 5355))
            except:
                client.close()
                return False

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

def writeLog(client, data=''):
    separator = '='*50
    fopen = open('./asker.log', 'a')
    fopen.write('Time: %s\nIP: %s\nPort: %d\nData: %s\n%s\n\n' %(time.ctime(), client[0], client[1], data, separator))
    fopen.close()

def serve_llmnr_requests(host, port):
    return


def main():
    try:
        threads = []

        if args.llmnr is not None:
            ThreadedServerUDP('224.0.0.252', 5355).listen()
            #ThreadedServerUDP("0.0.0.0", 5355).listen()
    except:
        print(sys.exc_info()[0])
        print(sys.exc_info()[1])
        print(sys.exc_info()[2])

if __name__ == '__main__':
    main()

