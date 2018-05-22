from scapy.all import *
import argparse

parser = argparse.ArgumentParser(description='single-packet LLMNR response tester')
parser.add_argument('rname', help='name of the query to respond to')
args = parser.parse_args()

def llmnr_responder():

    def handle_response(pkt):

        assembler_packet = IP(dst='google.com')
        assembler_packet.show2()
        local_ip = assembler_packet[IP].src

        if DNSQR in pkt and pkt[DNSQR].qname == (args.rname+'.'):
            print "Got a hit! " + pkt.summary()
            if pkt[DNSQR].qtype == 255:
                rebuilt_query = pkt[DNSQR]
                rebuilt_query.qtype = 1
                snd_pkt = IP(dst=pkt[IP].src) / UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / LLMNRResponse(id=pkt[LLMNRQuery].id, qd=rebuilt_query, an=DNSRR(type=1, rdata=local_ip, rrname=pkt[DNSQR].qname, ttl=1))
                print('sending: ')
                snd_pkt.show2()
                send(snd_pkt)
                
                """
                assembler_packet = IPv6(dst='')
                assembler_packet.show2()
                local_ip = assembler_packet[IP].src
                snd_pkt = IPv6(dst=pkt[IP].src, ttl=1) / UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / LLMNRResponse(qd=pkt[DNSQR], ar=DNSRR(type=28, rdata=local_ip, rrname=pkt[DNSQR].qname))
                print('sending: ')
                snd_pkt.show2()
                send(snd_pkt)
                """
            elif pkt[DNSQR].qtype == 1:
                snd_pkt = IP(dst=pkt[IP].src) / UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / LLMNRResponse(id=pkt[LLMNRQuery].id, qd=pkt[DNSQR], an=DNSRR(type=1, rdata=local_ip, rrname=pkt[DNSQR].qname, ttl=1))
                print('sending: ')
                snd_pkt.show2()
                send(snd_pkt)

            """
            elif pkt[DNSQR].qtype == 28:
                snd_pkt = IPv6(dst=pkt[IP].src, ttl=1) / UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / LLMNRResponse(qd=pkt[DNSQR], ar=DNSRR(type=28, rdata=local_ip, rrname=pkt[DNSQR].qname))
                print('sending: ')
                snd_pkt.show2()
                send(snd_pkt)
            """

    return handle_response

sniff(filter='dst host 224.0.0.252', prn=llmnr_responder())
