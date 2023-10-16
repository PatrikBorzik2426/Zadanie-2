from scapy.all import *
import yaml
from ruamel.yaml import *
import argparse

parser=argparse.ArgumentParser(description='Analyzator packetov')
parser.add_argument('-p','--port',type=str,help='port that we want to filter')

yaml_ruamel=YAML()
yaml_ruamel.indent(mapping=2, sequence=4, offset=2)
yaml_ruamel.default_flow_style=False
yaml_ruamel.allow_unicode=True
yaml_ruamel.width=48

yaml_general=[]
completed_com=[]
incompleted_com=[]
all_com=[]
ipv4_senders=[]
all_com_data=[]


hex_stews={}

class generalPacket:
    packet_id=None
    packet_length=None
    packet_length_medium=None
    packet_frame_type=None
    source_mac=None
    destination_mac=None
    
    tcp_flag=''
    
    def __init__(self,packet_id,packet_length,packet_frame_type,source_mac,destination_mac,packet):
        self.packet_id=packet_id
        self.packet_length=packet_length
        if packet_length <= 60:
            self.packet_length_medium=64
        else:
            self.packet_length_medium=self.packet_length+4
        self.packet_frame_type=packet_frame_type
        self.source_mac=source_mac
        self.destination_mac=destination_mac

        
class ieeetLlcSnap(generalPacket):
    pid=None
    
    def __init__(self,general_packet,packet,yaml_data):
        super().__init__(general_packet.packet_id,general_packet.packet_length,general_packet.packet_frame_type,general_packet.source_mac,general_packet.destination_mac,packet)
        self.resolve(packet,yaml_data)
        
    def resolve(self,packet,yaml_data):
        pid_location1=int(bytes(packet[20:22]).hex(),16)
        pid_location2=int(bytes(packet[46:48]).hex(),16)
        
        for i in yaml_data['pid']: 
             
            if i == pid_location1 :
                pid_type=yaml_data['pid'][i]
                self.pid=pid_type        
                return self
        
            if i == pid_location2 : 
                pid_type=yaml_data['pid'][i]
                self.pid=pid_type        
                return self
        
class ieeeLlc(generalPacket):
    sap=None
    
    def __init__(self,general_packet,packet,yaml_data):
        super().__init__(general_packet.packet_id,general_packet.packet_length,general_packet.packet_frame_type,general_packet.source_mac,general_packet.destination_mac,packet)
        self.resolve(packet,yaml_data)

        
    def resolve(self,packet,yaml_data):
        sap_location=int(bytes(packet[15:16]).hex(),16)
        
        for i in yaml_data['sap']: 
             
            if i == sap_location: #? Choosing an ether_type based on 13th-14th byte
                sap_type=yaml_data['sap'][i]
                self.sap=sap_type
                break
        
        return self
                   
class ieeeRaw(generalPacket):
    protocol=None
    def __init__(self,general_packet,packet,yaml_data):
        super().__init__(general_packet.packet_id,general_packet.packet_length,general_packet.packet_frame_type,general_packet.source_mac,general_packet.destination_mac,packet)
        
   
class ethernetTwo(generalPacket):
    destination_ip=''
    source_ip=''
    protocol="unknown"
    inner_protocol=None
    inner_protocol_detail=None
    source_port=None
    destination_port=None
    
    def __init__(self,general_packet,protocol,packet):
        super().__init__(general_packet.packet_id,general_packet.packet_length,general_packet.packet_frame_type,general_packet.source_mac,general_packet.destination_mac,packet)
        self.protocol=protocol
        self.resolve(packet)
        
    def resolve(self,packet):
        for i in range(26,30,1):
            if not i == 29:
                self.source_ip+=str(int(bytes(packet[i:i+1]).hex(),16))+'.'
                self.destination_ip+=str(int(bytes(packet[i+4:i+5]).hex(),16))+'.'
            else:
                self.source_ip+=str(int(bytes(packet[i:i+1]).hex(),16))
                self.destination_ip+=str(int(bytes(packet[i+4:i+5]).hex(),16))

class threeHandshake():
    attempt_to_start=False
    started=False
    finished=False
    communication_data=[]
    
    source_port=''
    destination_port=''
    source_ip=''
    destination_ip=''
    
    def __init__(self):
        self.attempt_to_start=True

class icmpCommunication():
    source_ip=''
    destination_ip=''
    identifier='' 
    communication_data=[]
    
    finished=False
    
    def __init__(self):
        self.communication_data=[]

class tftpCommunication():
    source_port=0
    destination_port=0
    finished=False
    communication_data=[]
    
    def __init__(self):
        self.finished=False
    
    
def process_params(packet,id,port):
       
    destination=bytes(packet[:6]).hex()
    source=bytes(packet[6:12]).hex()
    
    source=':'.join([source[i:i+2] for i in range(0, len(source), 2)])
    destination=':'.join([destination[i:i+2] for i in range(0, len(destination), 2)])
    length=len(packet)
    ethernet_type=frame_type_function(packet)
    
    general_frame=generalPacket(id,length,ethernet_type,source,destination,packet)
    
    hex_stew=bytes(packet).hex()
    hex_stew = ' '.join(hex_stew[i:i+2] for i in range(0, len(hex_stew), 2)).upper()
    hex_stew = '\n'.join(hex_stew[i:i+47] for i in range(0, len(hex_stew), 48)).upper()
    hex_stew = hex_stew+"\n"
    
    hex_stew=ruamel.yaml.scalarstring.LiteralScalarString(hex_stew)
    
    hex_stews.update({general_frame.packet_id: hex_stew})  
    
    return final_resolve(general_frame,packet,port)
   
    
    
def frame_type_function(packet):
    frame_part_length=int(bytes(packet[12:14]).hex(),16)
    
    if frame_part_length >= 1500:     
        ethernet_type='Ethernet II'
        return ethernet_type

    else:
        non_ethernet_value=bytes(packet[14:16]).hex()
        
        if non_ethernet_value == 'aaaa': #? IEEE 802.3 LLC & SNAP
            ethernet_type='IEEE 802.3 LLC & SNAP'
        elif non_ethernet_value == 'ffff': #? IEEE 802.3 RAW
            ethernet_type='IEEE 802.3 RAW'
        else:
            ethernet_type='IEEE 802.3 LLC'
        return ethernet_type
       
def final_resolve(general_packet,packet,port):
    #Reading possible file-types from external file
    with open('./types.yaml','r') as file:
        yaml_data=yaml.safe_load(file)
    
    if general_packet.packet_frame_type == 'IEEE 802.3 LLC & SNAP':
        final_frame=ieeetLlcSnap(general_packet,packet,yaml_data)
        yaml_creator(final_frame,packet,port)
    elif general_packet.packet_frame_type == 'IEEE 802.3 RAW':
        final_frame=ieeeRaw(general_packet,packet,yaml_data)
        yaml_creator(final_frame,packet,port)
    elif general_packet.packet_frame_type == 'Ethernet II':
        frame_part_length=int(bytes(packet[12:14]).hex(),16)

        for i in yaml_data['ether_type']:  
            if i == frame_part_length:               #? Choosing an ether_type based on 13th-14th byte
                ethernet_protocol=yaml_data['ether_type'][i]
                final_frame=ethernetTwo(general_packet,ethernet_protocol,packet)
                break
            else:
                final_frame=ethernetTwo(general_packet,"unknown",packet)           
        
        
        if final_frame.protocol == 'ipv4':
            yaml_creator(solver_inner_protocol(final_frame,packet,yaml_data,port),packet,port)
        elif final_frame.protocol == 'arp' and port=='arp':
            arp_check_comm(final_frame,packet,yaml_data)
            yaml_creator(final_frame,packet,port)
        else:
            yaml_creator(final_frame,packet,port)
    else:
        final_frame=ieeeLlc(general_packet,packet,yaml_data)
        yaml_creator(final_frame,packet,port)
    return final_frame

def solver_inner_protocol(final_frame,packet,yaml_data,port):
    
    ip_header_len=14+int(bytes(packet[14:15]).hex()[1:2],16)*4
    

    if final_frame.protocol == 'ipv4':
        inner_protocol=int(bytes(packet[23:24]).hex(),16)
        final_frame.source_port=int(bytes(packet[ip_header_len:ip_header_len+2]).hex(),16)
        final_frame.destination_port=int(bytes(packet[ip_header_len+2:ip_header_len+4]).hex(),16)
                
        for i in yaml_data['ipv4_protocol']:  
            if i == inner_protocol:               
                final_frame.inner_protocol=yaml_data['ipv4_protocol'][i]
                break
        
        if final_frame.inner_protocol == 'udp':
            for i in yaml_data['udp_protocol']:  
                if (i == final_frame.destination_port) or (i==final_frame.source_port):               
                    final_frame.inner_protocol_detail=yaml_data['udp_protocol'][i]
                    
                    if final_frame.inner_protocol_detail=='tftp' and port=='tftp':
                        tftp_check(final_frame,packet)
                        
                    return final_frame
                
            final_frame.inner_protocol_detail='unknown'
            
            if final_frame.inner_protocol_detail=='unknown' and port=='tftp' and len(all_com)!=0:
                tftp_check(final_frame,packet)
            return final_frame
        
        elif final_frame.inner_protocol == 'tcp':     
            for i in yaml_data['tcp_protocol']:  
                if (i == final_frame.destination_port) or (i==final_frame.source_port): 
                    final_frame.inner_protocol_detail=yaml_data['tcp_protocol'][i]
                    
                    if final_frame.inner_protocol_detail == port:
                        check_communication(final_frame,packet)
                    
                    return final_frame
            final_frame.inner_protocol_detail='unknown'
            return final_frame
        else:
            if final_frame.inner_protocol == 'icmp' and port=='icmp':
                icmp_check_comm(final_frame,packet,yaml_data)
            return final_frame
        
    else:
        return final_frame

def tftp_check(analyzed_frame,packet):
    udp_start=(14+int(bytes(packet[14:15]).hex()[1:2],16)*4)
    source_port=int(bytes(packet[udp_start:udp_start+2]).hex(),16)
    destination_port=int(bytes(packet[udp_start+2:udp_start+4]).hex(),16)
    udp_len=int(bytes(packet[udp_start+4:udp_start+6]).hex(),16)-12
    tftp_opcode=int(bytes(packet[udp_start+8:udp_start+10]).hex(),16)
    
    analyzed_frame.source_port=source_port
    analyzed_frame.destination_port=destination_port
    
    setattr(analyzed_frame,'udp_len',udp_len)
    setattr(analyzed_frame,'tftp_opcode',tftp_opcode)
    
    if analyzed_frame.inner_protocol_detail=='tftp':
        new_comm=tftpCommunication()
        new_comm.communication_data=[]
        new_comm.source_port=source_port
        new_comm.destination_port=destination_port
        setattr(analyzed_frame,'finished',False)
        
        new_comm.communication_data.append(analyzed_frame)
        
        all_com.append(new_comm)
        
        print(analyzed_frame.packet_id, analyzed_frame.source_port, analyzed_frame.destination_port, analyzed_frame.udp_len)

        return
    else:
        for com in all_com:
            for inner_com in com.communication_data:
                if inner_com.source_port == analyzed_frame.destination_port and inner_com.destination_port == analyzed_frame.source_port and com.finished==False:
                    
                    analyzed_frame.inner_protocol_detail=com.communication_data[0].inner_protocol_detail
                    com.communication_data.append(analyzed_frame)
                    
                    if analyzed_frame.tftp_opcode == 5:
                        com.finished=True
                    
                    return
                elif inner_com.source_port == analyzed_frame.source_port and inner_com.destination_port == analyzed_frame.destination_port and com.finished==False:
                    
                    analyzed_frame.inner_protocol_detail=com.communication_data[0].inner_protocol_detail
                    com.communication_data.append(analyzed_frame)
                    
                    if analyzed_frame.tftp_opcode == 5:
                        com.finished=True
                    
                    return
                
                elif inner_com.source_port==analyzed_frame.destination_port and inner_com.destination_port == 69 and len(com.communication_data)==1 and com.finished==False:
                        
                    analyzed_frame.inner_protocol_detail=com.communication_data[0].inner_protocol_detail
                    com.communication_data.append(analyzed_frame)
                    
                    if analyzed_frame.tftp_opcode == 5:
                        com.finished=True
                    
                    return
                    
    new_comm=tftpCommunication()
    new_comm.communication_data=[]
    new_comm.source_port=source_port
    new_comm.destination_port=destination_port
    
    new_comm.communication_data.append(analyzed_frame)
    
    all_com.append(new_comm)
    
    print(analyzed_frame.packet_id, analyzed_frame.source_port, analyzed_frame.destination_port, analyzed_frame.udp_len)
    
def arp_check_comm(analyzed_frame,packet,yaml_data):
    start_of_arp=14
    opcode=''
    
    if int(bytes(packet[start_of_arp+6:start_of_arp+8]).hex(),16) == 1:
        opcode='request'
    else:
        opcode='reply'
    
    sender_mac=bytes(packet[start_of_arp+8:start_of_arp+14]).hex()
    sender_mac=':'.join([sender_mac[i:i+2] for i in range(0, len(sender_mac), 2)])
    sender_ip=''
    
    target_mac=bytes(packet[start_of_arp+18:start_of_arp+24]).hex()
    target_mac=':'.join([target_mac[i:i+2] for i in range(0, len(target_mac), 2)])
    target_ip=''
    
    for i in range(start_of_arp+14,start_of_arp+18,1):
        if not i == start_of_arp+17:
            sender_ip+=str(int(bytes(packet[i:i+1]).hex(),16))+'.'
            target_ip+=str(int(bytes(packet[i+10:i+11]).hex(),16))+'.'
        else:
            sender_ip+=str(int(bytes(packet[i:i+1]).hex(),16))
            target_ip+=str(int(bytes(packet[i+10:i+11]).hex(),16))
    
    
    setattr(analyzed_frame,'sender_mac',sender_mac)
    setattr(analyzed_frame,'sender_ip',sender_ip)
    setattr(analyzed_frame,'target_mac',target_mac)
    setattr(analyzed_frame,'target_ip',target_ip)
    setattr(analyzed_frame,'has_pair',False)
    setattr(analyzed_frame,'opcode',opcode)

    all_com.append(analyzed_frame)
    
    
    
def icmp_check_comm(analyzed_frame,packet,yaml_data):
    icmp_start=(14+int(bytes(packet[14:15]).hex()[1:2],16)*4)
    icmp_type=int(bytes(packet[icmp_start:icmp_start+1]).hex(),16)
    
    icmp_identifier=int(bytes(packet[icmp_start+4:icmp_start+6]).hex(),16)
    icmp_sequence=int(bytes(packet[icmp_start+6:icmp_start+8]).hex(),16)
    
    frag_identifier=int(bytes(packet[18:20]).hex(),16)
    mf_flag=(packet[20]>>5) & 0x01
    frag_offset= (int(bytes(packet[20:22]).hex(),16) & 0x1FFF) *8
    
    print(analyzed_frame.packet_id,frag_identifier,mf_flag,icmp_identifier, frag_offset)
    
    
    
    for i in yaml_data['icmp_code']:
        if i==icmp_type:
            icmp_type=yaml_data['icmp_code'][i]
            break
    
    setattr(analyzed_frame,'icmp_type',icmp_type)
    setattr(analyzed_frame,'icmp_sequence',icmp_sequence)
    setattr(analyzed_frame,'icmp_identifier',icmp_identifier)
    setattr(analyzed_frame,'frag_identifier',frag_identifier)
    setattr(analyzed_frame,'mf_flag',mf_flag)
    setattr(analyzed_frame,'frag_offset',frag_offset)
    
    if analyzed_frame.packet_id==1695 or analyzed_frame.packet_id==1696 :
        pass
 
    
    if analyzed_frame.icmp_type != 'Time Exceeded':

        for com in all_com:
            
            
            if (com.destination_ip == analyzed_frame.destination_ip and com.source_ip == analyzed_frame.source_ip and (com.identifier == analyzed_frame.icmp_identifier or icmp_identifier==1 or icmp_type==97)):
                if com.finished==False:
                    com.communication_data.append(analyzed_frame)
                    return
                
            elif (com.destination_ip == analyzed_frame.source_ip and com.source_ip == analyzed_frame.destination_ip and (com.identifier == analyzed_frame.icmp_identifier or icmp_identifier==1 or icmp_type==97)):
                if com.finished==False:
                    com.communication_data.append(analyzed_frame)
                    return
    
    if analyzed_frame.icmp_type == 'Time Exceeded':
        for com in all_com:
            if com.finished==False:
                if (com.source_ip == analyzed_frame.destination_ip):
                    for data in com.communication_data:
                        if data.icmp_sequence==int(bytes(packet[-2:]).hex(),16):
                            analyzed_frame.icmp_sequence=int(bytes(packet[-2:]).hex(),16)
                            
                            com.communication_data.append(analyzed_frame)
                            com.finished=True
                            return
        
    
    new_comm = icmpCommunication()
    
    new_comm.destination_ip=analyzed_frame.destination_ip
    new_comm.source_ip=analyzed_frame.source_ip
    new_comm.identifier=icmp_identifier
    new_comm.communication_data=[]
    
    new_comm.communication_data.append(analyzed_frame)
    
    all_com.append(new_comm)         
    
def check_communication(analyzed_frame,packet):
    tcp_flag_position=14+int(bytes(packet[14:15]).hex()[1:2])*4+14
    tcp_flag= int(bytes(packet[tcp_flag_position-1:tcp_flag_position]).hex())
    
    analyzed_frame.tcp_flag=tcp_flag
        
    if(tcp_flag==2):        #? If we see a flag with SYN we create an handshake object
        
        for com in all_com:
            if com.finished==False:
                            
                last_communication_len=len(com.communication_data)
                
                if com.communication_data[last_communication_len-1].tcp_flag==10 or com.communication_data[last_communication_len-1].tcp_flag==11:
                    if com.communication_data[last_communication_len-2].tcp_flag==11 or com.communication_data[last_communication_len-2].tcp_flag==10:
                        if last_communication_len-3>=0 and (com.communication_data[last_communication_len-3].tcp_flag==11 or com.communication_data[last_communication_len-3].tcp_flag==10):
                            if last_communication_len-4>=0 and (com.communication_data[last_communication_len-4].tcp_flag==11 or com.communication_data[last_communication_len-4].tcp_flag==10):
                                com.finished=True
                            else:
                                com.finished=True
                                
                elif(com.communication_data[last_communication_len-1].tcp_flag==4 or com.communication_data[last_communication_len-1].tcp_flag==14):
                    com.finished=True
                    
            
        new_handshake=threeHandshake()
               
        new_handshake.attempt_to_start=True
        new_handshake.destination_ip=analyzed_frame.destination_ip
        new_handshake.source_ip=analyzed_frame.source_ip
        new_handshake.source_port=analyzed_frame.source_port
        new_handshake.destination_port=analyzed_frame.destination_port
        new_handshake.communication_data=[]
        
        new_handshake.communication_data.append(analyzed_frame)
        
        all_com.append(new_handshake)
        
    elif len(all_com)!=0 and all_com[len(all_com)-1].attempt_to_start==True:
        for com in all_com:
            if com.attempt_to_start==True:    
                
                if com.destination_port == analyzed_frame.destination_port and com.source_port == analyzed_frame.source_port and com.source_ip == analyzed_frame.source_ip and com.destination_ip == analyzed_frame.destination_ip :
                    
                    com.communication_data.append(analyzed_frame)
                    
                    if len(com.communication_data) == 4:
                        if com.communication_data[0].tcp_flag==2 and com.communication_data[1].tcp_flag==12 and com.communication_data[2].tcp_flag==10:
                            com.started = True
                            
                            return
                        elif (com.communication_data[0]==2 or com.communication_data[1]==2) and (com.communication_data[2]==10 or com.communication_data[3]==10):
                            com.started = True
                            return
                    
                    return
                            
                elif com.destination_port == analyzed_frame.source_port and com.source_port==analyzed_frame.destination_port and com.source_ip == analyzed_frame.destination_ip and com.destination_ip == analyzed_frame.source_ip :
                    
                    com.communication_data.append(analyzed_frame)
                    
                    if len(com.communication_data) == 4:
                        if com.communication_data[0].tcp_flag==2 and com.communication_data[1].tcp_flag==12 and com.communication_data[2].tcp_flag==10:
                            com.started = True
                            return
                        elif (com.communication_data[0]==2 or com.communication_data[1]==2) and (com.communication_data[2]==10 or com.communication_data[3]==10):
                            com.started = True
                            return
                    return
            
    else:
                
        for com in all_com:
            
            last_communication_len=len(com.communication_data)

            if com.communication_data[last_communication_len-1].tcp_flag==4 or com.communication_data[last_communication_len-1].tcp_flag==14:
                com.finished=True
                return
            elif com.communication_data[last_communication_len-1].tcp_flag==10:
                if com.communication_data[last_communication_len-2].tcp_flag==11:
                        if last_communication_len-3>=0 and (com.communication_data[last_communication_len-3].tcp_flag==11 or com.communication_data[last_communication_len-3].tcp_flag==10):
                            
                            if last_communication_len-4>=0 and com.communication_data[last_communication_len-4].tcp_flag==11 or com.communication_data[last_communication_len-4].tcp_flag==10 :
                                com.finished=True
                                return
                            else:
                                com.finished=True
                                return
                
        
        for com in all_com:
            if com.destination_port == analyzed_frame.destination_port and com.source_port == analyzed_frame.source_port and com.source_ip == analyzed_frame.source_ip and com.destination_ip == analyzed_frame.destination_ip :
                if com.finished == False:
                    com.communication_data.append(analyzed_frame)
                return
                
            elif com.destination_port == analyzed_frame.source_port and com.source_port==analyzed_frame.destination_port and com.source_ip == analyzed_frame.destination_ip and com.destination_ip == analyzed_frame.source_ip :
                if com.finished == False:
                    com.communication_data.append(analyzed_frame)
                return
                
    
        

            
        new_handshake=threeHandshake()
        
        #TODO pozrieť sa na kontrolu FIN tak, že pri SYN pozriem na prechadzajúce vytvorené spojenie a presortujem vždy posledné začaté
        new_handshake.attempt_to_start=False
        new_handshake.destination_ip=analyzed_frame.destination_ip
        new_handshake.source_ip=analyzed_frame.source_ip
        new_handshake.source_port=analyzed_frame.source_port
        new_handshake.destination_port=analyzed_frame.destination_port
        new_handshake.communication_data=[]
        
        new_handshake.communication_data.append(analyzed_frame)
        
        all_com.append(new_handshake)
        
def tftp_yaml_creator():
    i=1
                    
    for com in all_com:
        
        number_of_replies=0
        number_of_requests=0
        y=0
        
        all_inner_com=[]                          
        
        for inner_com in com.communication_data:
            
            data={
                'frame_number': inner_com.packet_id,
                'len_frame_pcap': inner_com.packet_length,
                'len_frame_medium': inner_com.packet_length_medium,
                'frame_type': inner_com.packet_frame_type,
                'src_mac': inner_com.source_mac,
                'dst_mac': inner_com.destination_mac,
            }
            
            data.update({'ether_type': inner_com.protocol})
            data.update({'src_ip': inner_com.source_ip})
            data.update({'dst_ip': inner_com.destination_ip})
            data.update({'protocol': inner_com.inner_protocol})
            data.update({'src_port': inner_com.source_port})
            data.update({'dst_port': inner_com.destination_port})
            data.update({'app_protocol': inner_com.inner_protocol_detail})
            data.update({'hexa_frame':  hex_stews.get(inner_com.packet_id)}) 
            
            all_inner_com.append(data)              
            
        if (com.communication_data[0].destination_port==69 and com.communication_data[len(com.communication_data)-1].udp_len==0 or com.communication_data[len(com.communication_data)-1].tftp_opcode==5) and (com.communication_data[len(com.communication_data)-1].udp_len<512 or com.communication_data[len(com.communication_data)-1].tftp_opcode==5) :
            com_data={
                "number_comm": i,
                "packets": all_inner_com
            }
            
            completed_com.append(com_data)        
        else:
            com_data={
                "number_comm": i,
                "packets": all_inner_com
            }
            
            
            incompleted_com.append(com_data)
        
        i+=1         

    
def arp_yaml_creator():
   
    all_inner_com=[]   
    arp_incompleted_req=[]
    arp_incompleted_res=[]
       
    for com in all_com:
        for i in range(len(all_com)):
            if com == all_com[i]:
                continue
            else:
                if com.sender_mac==all_com[i].target_mac and com.sender_ip==all_com[i].target_ip and all_com[i].has_pair==False:
                    if com.opcode=='reply' and all_com[i].opcode=='request':
                        com.has_pair=True
                        all_com[i].has_pair=True
                    elif com.opcode=='request' and all_com[i].opcode=='reply':
                        com.has_pair=True
                        all_com[i].has_pair=True

    
    for com in all_com:
        if com.has_pair==True:
            data={
                    'frame_number': com.packet_id,
                    'len_frame_pcap': com.packet_length,
                    'len_frame_medium': com.packet_length_medium,
                    'frame_type': com.packet_frame_type,
                    'src_mac': com.sender_mac,
                    'dst_mac': com.target_mac,
                }
                
            data.update({'ether_type': com.protocol})
            data.update({'arp_opcode': com.opcode})
            data.update({'src_ip': com.sender_ip})
            data.update({'dst_ip': com.target_ip})
            data.update({'hexa_frame':  hex_stews.get(com.packet_id)}) 
            
            all_inner_com.append(data)
            
        else:
            if com.opcode=='reply':
                data={
                        'frame_number': com.packet_id,
                        'len_frame_pcap': com.packet_length,
                        'len_frame_medium': com.packet_length_medium,
                        'frame_type': com.packet_frame_type,
                        'src_mac': com.sender_mac,
                        'dst_mac': com.target_mac,
                    }
                    
                data.update({'ether_type': com.protocol})
                data.update({'arp_opcode': com.opcode})
                data.update({'src_ip': com.sender_ip})
                data.update({'dst_ip': com.target_ip})
                data.update({'hexa_frame':  hex_stews.get(com.packet_id)}) 

                
                arp_incompleted_res.append(data)
                                
            else:
                data={
                        'frame_number': com.packet_id,
                        'len_frame_pcap': com.packet_length,
                        'len_frame_medium': com.packet_length_medium,
                        'frame_type': com.packet_frame_type,
                        'src_mac': com.sender_mac,
                        'dst_mac': com.target_mac,
                    }
                    
                data.update({'ether_type': com.protocol})
                data.update({'arp_opcode': com.opcode})
                data.update({'src_ip': com.sender_ip})
                data.update({'dst_ip': com.target_ip})
                data.update({'hexa_frame':  hex_stews.get(com.packet_id)}) 
                
                arp_incompleted_req.append(data)

    com_data={
        "number_comm": 1,
        "packets": all_inner_com
    }
    
    com_data_res={
        "number_comm": 2,
        "packets": arp_incompleted_res
    }
    
    com_data_req={
        "number_comm": 1,
        "packets": arp_incompleted_req
    }
    
    if len(all_inner_com)>=1:
        completed_com.append(com_data)
        
    if len(arp_incompleted_req)>=1:
        incompleted_com.append(com_data_req)
    
    if len(arp_incompleted_res)>=1:
        incompleted_com.append(com_data_res)
    
      
    
            
def icmp_yaml_creator(port):
    if port != 'all':
        i=1
                        
        for com in all_com:
            
            number_of_replies=0
            number_of_requests=0
            y=0
            
            all_inner_com=[]
            
            if com.communication_data[y].mf_flag==1:
                while(y<len(com.communication_data)-1):
                    if com.communication_data[y+1].mf_flag!=1:
                        com.communication_data[y+1].icmp_type=com.communication_data[y].icmp_type
                    y+=1                            
            
            for inner_com in com.communication_data:
                
                data={
                    'frame_number': inner_com.packet_id,
                    'len_frame_pcap': inner_com.packet_length,
                    'len_frame_medium': inner_com.packet_length_medium,
                    'frame_type': inner_com.packet_frame_type,
                    'src_mac': inner_com.source_mac,
                    'dst_mac': inner_com.destination_mac,
                }
                
                data.update({'ether_type': inner_com.protocol})
                data.update({'src_ip': inner_com.source_ip})
                data.update({'dst_ip': inner_com.destination_ip})
                if inner_com.mf_flag == 1:
                    data.update({'id': inner_com.frag_identifier})
                    data.update({'flags_mf': True})
                    data.update({'frag_offset': inner_com.frag_offset})
                    data.update({'hexa_frame':  hex_stews.get(inner_com.packet_id)}) 
                else:
                    data.update({'id': inner_com.frag_identifier})
                    data.update({'flags_mf': False})
                    data.update({'frag_offset': inner_com.frag_offset})
                    data.update({'protocol': inner_com.inner_protocol_detail})
                    data.update({'icmp_type': inner_com.icmp_type})
                    data.update({'icmp_id': inner_com.icmp_identifier})
                    data.update({'icmp_id': inner_com.icmp_sequence})
                    data.update({'hexa_frame':  hex_stews.get(inner_com.packet_id)}) 
                
                all_inner_com.append(data)
                
                if inner_com.icmp_type == 'Echo Reply' or inner_com.icmp_type == 'Time Exceeded':
                    number_of_replies+=1
                if inner_com.icmp_type == 'Echo Request':
                    number_of_requests+=1
                
            if number_of_requests == number_of_replies :
                com_data={
                    "number_comm": i,
                    "src_comm": com.source_ip,
                    "dst_comm": com.destination_ip,
                    "packets": all_inner_com
                }
                
                if len(all_inner_com)>=1:
                    completed_com.append(com_data)        

            else:
                com_data={
                    "number_comm": i,
                    #"src_comm": com.source_ip,
                    #"dst_comm": com.destination_ip,
                    "packets": all_inner_com
                }
                
                if len(all_inner_com)>=1:
                    incompleted_com.append(com_data)
            
            i+=1         

def yaml_creator(analyzed_packet,packet,port):
   

    if port == 'all' or (analyzed_packet.packet_frame_type == 'Ethernet II' and (analyzed_packet.protocol == port or analyzed_packet.inner_protocol==port or analyzed_packet.inner_protocol_detail==port)):

            data={
                'frame_number': analyzed_packet.packet_id,
                'len_frame_pcap': analyzed_packet.packet_length,
                'len_frame_medium': analyzed_packet.packet_length_medium,
                'frame_type': analyzed_packet.packet_frame_type,
                'src_mac': analyzed_packet.source_mac,
                'dst_mac': analyzed_packet.destination_mac,
            }

            if hasattr(analyzed_packet,'pid'):
                data.update({'pid': analyzed_packet.pid})
            elif hasattr(analyzed_packet,'sap'):
                data.update({'sap': analyzed_packet.sap})
            elif analyzed_packet.packet_frame_type == 'Ethernet II':
                data.update({'ether_type': analyzed_packet.protocol})
                data.update({'src_ip': analyzed_packet.source_ip})
                data.update({'dst_ip': analyzed_packet.destination_ip})
                if analyzed_packet.protocol != 'arp':
                    data.update({'protocol': analyzed_packet.inner_protocol})
                if analyzed_packet.inner_protocol == 'udp' or analyzed_packet.inner_protocol == 'tcp':
                    data.update({'src_port': analyzed_packet.source_port})
                    data.update({'dst_port': analyzed_packet.destination_port})
                    data.update({'app_protocol': analyzed_packet.inner_protocol_detail})
            else:
                data.update({'ether_type': analyzed_packet.protocol})

            data.update({'hexa_frame':  hex_stews.get(analyzed_packet.packet_id)}) 


            yaml_general.append(data)                              
                
def tcp_yaml_creator(port):
    if port != 'all':
        i=1
                        
        for com in all_com:
            
            all_inner_com=[]
            
            for inner_com in com.communication_data:
                data={
                    'frame_number': inner_com.packet_id,
                    'len_frame_pcap': inner_com.packet_length,
                    'len_frame_medium': inner_com.packet_length_medium,
                    'frame_type': inner_com.packet_frame_type,
                    'src_mac': inner_com.source_mac,
                    'dst_mac': inner_com.destination_mac,
                }
                
                data.update({'ether_type': inner_com.protocol})
                data.update({'src_ip': inner_com.source_ip})
                data.update({'dst_ip': inner_com.destination_ip})
                data.update({'protocol': inner_com.inner_protocol})
                data.update({'src_port': inner_com.source_port})
                data.update({'dst_port': inner_com.destination_port})
                data.update({'app_protocol': inner_com.inner_protocol_detail})
                data.update({'hexa_frame':  hex_stews.get(inner_com.packet_id)}) 
                
                all_inner_com.append(data)
                
            if com.started==True and com.finished==True:
                com_data={
                    "number_comm": i,
                    "src_comm": com.source_ip,
                    "dst_comm": com.destination_ip,
                    "packets": all_inner_com
                }
                
                if len(all_inner_com)>=1:
                    completed_com.append(com_data)        

            elif (com.started == False and com.finished==True) or (com.finished== False and com.started == True)  and len(incompleted_com)==0:
                com_data={
                    "number_comm": i,
                    #"src_comm": com.source_ip,
                    #"dst_comm": com.destination_ip,
                    "packets": all_inner_com
                }
                
                if len(all_inner_com)>=1:
                    incompleted_com.append(com_data)
            
            i+=1

def count_ip_nodes(analyzed_packet,all_nodes):
    if analyzed_packet.packet_frame_type == 'Ethernet II':
        if all_nodes.get(analyzed_packet.source_ip):
            all_nodes.update({
                analyzed_packet.source_ip:all_nodes.get(analyzed_packet.source_ip)+1
                })
        else:
            all_nodes.update({
                analyzed_packet.source_ip: 1
            })
    return all_nodes

def main():
    with open('./types.yaml','r') as file:
        yaml_data=yaml.safe_load(file)
    
    file_name='trace-26.pcap'
    project_name='PKS2023/24'
    pcap_file = './test_pcap_files/vzorky_pcap_na_analyzu/'+file_name

    args = parser.parse_args()
    port_true=False
    port = args.port
    port = 'pooper'
    
    for data in yaml_data['ipv4_protocol']:
        if yaml_data['ipv4_protocol'][data]==port:
            port_true=True
    for data in yaml_data['udp_protocol']:
        if yaml_data['udp_protocol'][data]==port:
            port_true=True
    for data in yaml_data['tcp_protocol']:
        if yaml_data['tcp_protocol'][data]==port:
            port_true=True
    for data in yaml_data['ether_type']:
        if yaml_data['ether_type'][data]==port:
            port_true=True
            
    if port_true==False:
        exit('Neznámy údaj, skús to znova!')

    packets= rdpcap(pcap_file) 
        
    id=1
    
    all_nodes={}
    
    for packet in packets:
        all_nodes=count_ip_nodes(process_params(bytes(packet),id,port),all_nodes)
        id+=1
        
    max_value = max(all_nodes.values())
    keys_with_max_value = [key for key, value in all_nodes.items() if value == max_value]
    
    if port == 'http' or port == 'https' or port == 'telnet' or port == 'ssh' or port =='ftp-data' or  port =='ftp-control':
        tcp_yaml_creator(port)
    elif port == 'icmp':
        icmp_yaml_creator(port)
    elif port == 'arp':
        arp_yaml_creator()
    elif port == 'tftp':
        tftp_yaml_creator()
    

    data_general={
        'name': project_name,
        'pcap_name': file_name,
        'packets': yaml_general
    }
    
    data={
        'name': project_name,
        'pcap_name': file_name,
        'filter_name' : port
    }
    if len(completed_com)>0:
        data.update({'complete_comms': completed_com})
        
    if len(incompleted_com)>0:
        data.update({'partial_comms': incompleted_com})

    iterable_items=all_nodes.items()
       
    
    for item in iterable_items:
        ipv4_data={
            "node": item[0],
            "number_of_sent_packets": item[1]
        }
       
        ipv4_senders.append(ipv4_data)                 
       
    all_nodes={
        'ipv4_senders': ipv4_senders
    }
    
    max_senders={
        "max_send_packets_by":keys_with_max_value
    }
    
    with open('./output_'+port+'.yaml','w') as file:
        yaml_ruamel.dump(data,file)
        
    
    with open('./output_general.yaml','w') as file:
        yaml_ruamel.dump(data_general,file)
        yaml_ruamel.dump(all_nodes,file)
        yaml_ruamel.dump(max_senders,file)


main()