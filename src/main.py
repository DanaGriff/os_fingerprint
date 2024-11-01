import scapy.all as scapy
import random
from models.ICMPResponse import ICMPResponse

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
    target_ip = "127.0.0.1"
    icmp_echo(target_ip)

if __name__ == '__main__':
    main()