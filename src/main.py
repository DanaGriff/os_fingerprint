import scapy.all as scapy
import random
from models.ICMPResponse import ICMPResponse
from models.TCPResponse import TCPResponse
import time

def tcp_sequence_test(target_ip, open_port):
    test_results = TCPResponse()

    packets = [
        scapy.IP(dst=target_ip) /
        scapy.TCP(dport=open_port, flags="S", window=1, options=[("WScale", 10), ("NOP", None), ("MSS", 1460), 
                                                                 ("Timestamp", (0xFFFFFFFF, 0)), ("SAckOK", "")]),

        scapy.IP(dst=target_ip) /
        scapy.TCP(dport=open_port, flags="S", window=63, options=[("MSS", 1400), ("WScale", 0), ("SAckOK", ""), 
                                                                  ("Timestamp", (0xFFFFFFFF, 0)), ("EOL", None)]),

        scapy.IP(dst=target_ip) /
        scapy.TCP(dport=open_port, flags="S", window=4, options=[("Timestamp", (0xFFFFFFFF, 0)), ("NOP", None), 
                                                                 ("NOP", None), ("WScale", 5), ("NOP", None), 
                                                                 ("MSS", 640)]),

        scapy.IP(dst=target_ip) /
        scapy.TCP(dport=open_port, flags="S", window=4, options=[("SAckOK", ""), ("Timestamp", (0xFFFFFFFF, 0)), 
                                                                 ("WScale", 10), ("EOL", None)]),

        scapy.IP(dst=target_ip) /
        scapy.TCP(dport=open_port, flags="S", window=16, options=[("MSS", 536), ("SAckOK", ""), 
                                                                  ("Timestamp", (0xFFFFFFFF, 0)), ("WScale", 10), 
                                                                  ("EOL", None)]),

        scapy.IP(dst=target_ip) /
        scapy.TCP(dport=open_port, flags="S", window=512, options=[("MSS", 265), ("SAckOK", ""), 
                                                                   ("Timestamp", (0xFFFFFFFF, 0))])
    ]

    for i, packet in enumerate(packets):
        response = scapy.sr1(packet, timeout=2, verbose=0)
        test_results.save_response(response, probe_number=i + 1)
        time.sleep(0.1)

    print(test_results)
    
def icmp_echo(target_ip):
    ie_results = ICMPResponse()
    
    #First ICMP probe
    type_of_service_probe_1 = 0
    icmp_code_probe_1 = 9
    seq_num_probe_1 = 295
    ip_id_probe_1 = random.randint(0, 65535)
    icmp_id_probe_1 = random.randint(0, 65535)
    
    icmp_probe_1 = (
        scapy.IP(dst=target_ip, flags="DF", tos=type_of_service_probe_1, id=ip_id_probe_1) /
        scapy.ICMP(type=8, code=icmp_code_probe_1, id=icmp_id_probe_1, seq=seq_num_probe_1) /
        (b'\x00' * 120)  # 120 bytes of 0x00 for the data payload
    )

    response_1 = scapy.sr1(icmp_probe_1, timeout=2)
    ie_results.save_first_probe(response_1)

    # Second ICMP probe
    type_of_service_probe_2 = 4
    icmp_code_probe_2 = 0
    seq_num_probe_2 = seq_num_probe_1 + 1
    ip_id_probe_2 = random.randint(0, 65535)
    icmp_id_probe_2 = icmp_id_probe_1 + 1
    
    icmp_probe_2 = (
        scapy.IP(dst=target_ip, flags="DF", tos=type_of_service_probe_2, id=ip_id_probe_2) /
        scapy.ICMP(type=8, code=icmp_code_probe_2, id=icmp_id_probe_2, seq=seq_num_probe_2) /
        (b'\x00' * 150)  # 150 bytes of 0x00 for the data payload
    )

    response_2 = scapy.sr1(icmp_probe_2, timeout=2)
    ie_results.save_second_probe(response_2)
    
    print(ie_results)
    
def main():
    # TODO: Add input from user
    target_ip = "10.0.0.9"
    open_port = 80
    # icmp_echo(target_ip)
    tcp_sequence_test(target_ip, open_port)

if __name__ == '__main__':
    main()