# Part 4 of UWCSE's Mininet-SDN project
#
# based on Lab Final from UCSC's Networking Class
# which is based on of_tutorial by James McCauley

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, IPAddr6, EthAddr

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp

log = core.getLogger()

# Convenience mappings of hostnames to ips
IPS = {
    "h10": "10.0.1.10",
    "h20": "10.0.2.20",
    "h30": "10.0.3.30",
    "serv1": "10.0.4.10",
    "hnotrust": "172.16.10.100",
}

# Convenience mappings of hostnames to subnets
SUBNETS = {
    "h10": "10.0.1.0/24",
    "h20": "10.0.2.0/24",
    "h30": "10.0.3.0/24",
    "serv1": "10.0.4.0/24",
    "hnotrust": "172.16.10.0/24",
}


class Part4Controller(object):
    '''
    A Connection object for that switch is passed to the __init__ function.
    '''

    def __init__(self, connection):
        print(connection.dpid)
        # Keep track of the connection to the switch so that we can
        # send it messages!
        self.connection = connection

        # This binds our PacketIn event listener
        connection.addListeners(self)
        # use the dpid to figure out what switch is being created
        if connection.dpid == 1:
            self.s1_setup()
        elif connection.dpid == 2:
            self.s2_setup()
        elif connection.dpid == 3:
            self.s3_setup()
        elif connection.dpid == 21:
            self.cores21_setup()
        elif connection.dpid == 31:
            self.dcs31_setup()
        else:
            print("UNKNOWN SWITCH")
            exit(1)

    def normal_behaviour(self):
        msg = of.ofp_flow_mod()
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
        self.connection.send(msg)

    def s1_setup(self):
        # put switch 1 rules here
        self.normal_behaviour()

    def s2_setup(self):
        # put switch 2 rules here
        self.normal_behaviour()

    def s3_setup(self):
        # put switch 3 rules here
        self.normal_behaviour()

    def cores21_setup(self):
        # put core switch rules here
        #block IMCP from hnotrust1
        block_icmp = of.ofp_flow_mod()
        block_icmp.match.dl_type = 0x0800 #IPv4
        block_icmp.match.nw_proto = 1 #ICMP
        block_icmp.match.nw_src = IPS["hnotrust"]
        self.connection.send(block_icmp)
        #print(f"BLOCK ICMP {block_icmp}\n")

        #block IP from hnotrust1 to serv1
        block_ip = of.ofp_flow_mod()
        block_ip.match.dl_type = 0x0800 #IPv4
        block_ip.match.nw_src = IPS["hnotrust"]
        block_ip.match.nw_dst = IPS["serv1"]
        self.connection.send(block_ip)
        #print(f"BLOCK IP {block_ip}\n")

        '''self.normal_behaviour()
        the actual routing of this is in handle packet in'''

    def dcs31_setup(self):
        # put datacenter switch rules here
        self.normal_behaviour()

    # used in part 4 to handle individual ARP packets
    # not needed for part 3 (USE RULES!)
    # causes the switch to output packet_in on out_port
    def resend_packet(self, packet_in, out_port):
        msg = of.ofp_packet_out()
        msg.data = packet_in
        action = of.ofp_action_output(port=out_port)
        msg.actions.append(action)
        self.connection.send(msg)

    def _handle_PacketIn(self, event):
        '''
        Packets not handled by the router rules will be
        forwarded to this method to be handled by the controller
        '''

        packet = event.parsed  # This is the parsed packet data.
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        packet_in = event.ofp  # The actual ofp_packet_in message.

        #get the input port to identify which use that port
        port_number = event.port
        #create a random address
        cores21_addr = EthAddr("01:02:03:04:05:06")

        print(packet)

        #reply to ARP request
        '''You might want the controller to proxy the ARP replies rather than flood them 
        all over the network depending on whether you know the MAC address of the machine
        the ARP request is looking for. To handle ARP packets in you should have an event
        listener set up to receive packet ins
        https://github.com/noxrepo/pox-doc/blob/master/include/apis.rst#id183'''
        if packet.type == packet.ARP_TYPE and packet.payload.opcode == arp.REQUEST:
            src_ip = packet.payload.protosrc
            dst_ip = packet.payload.protodst
            # create reply message
            arp_reply = arp()
            arp_reply.hwsrc = cores21_addr
            arp_reply.hwdst = packet.src
            arp_reply.opcode = arp.REPLY
            arp_reply.protosrc = dst_ip
            arp_reply.protodst = src_ip

            # wrap in ethernet wrapper
            ether = ethernet()
            ether.type = ethernet.ARP_TYPE
            ether.dst = packet.src
            ether.src = cores21_addr

            msg = of.ofp_flow_mod()
            msg.match.dl_type = 0x0800
            msg.match.nw_dst = src_ip
            msg.actions.append(of.ofp_action_dl_addr.set_dst(packet.src))
            msg.actions.append(of.ofp_action_output(port = port_number))
            self.connection.send(msg)

            ether.set_payload(arp_reply)
            self.resend_packet(ether.pack(), port_number)
            return

        print(
            "Unhandled packet from " + str(self.connection.dpid) + ":" + packet.dump()
        )



def launch():
    '''
    Starts the component
    '''

    def start_switch(event):
        log.debug("Controlling %s" % (event.connection,))
        Part4Controller(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)

