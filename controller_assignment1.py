from pox.core import core
import pox.lib.packet as pkt
import pox.lib.packet.ethernet as eth
import pox.lib.packet.arp as arp
import pox.lib.packet.icmp as icmp
import pox.lib.packet.ipv4 as ip
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr


log = core.getLogger()

table={}

rules=[# queues required for all dest hosts except h1 (h1 doesn't have queues)
       {'priority':1000,'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:03', 'TCPPort':40, 'queue':0, 'drop':False}, # cap at 30 Mb/s
       {'priority':1000,'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:02', 'TCPPort':60, 'queue':1, 'drop':False}, # cap at 150 Mb/s
       # => the first two example of rules have been added for you, you need now to add other rules to satisfy the assignment requirements. Notice that we will make decisions based on Ethernet address rather than IP address. Rate limiting is implemented by sending the pacet to the correct port and queue (the queues that you have specified in the topology file).
       
       # ARP rule inserted for all ports outside those specific above
       {'priority':600,'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:03', 'queue':0, 'drop':False}, # ARP uncapped
       {'priority':600,'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:02', 'queue':0, 'drop':False}, # ARP uncapped

       {'priority':600,'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:04', 'queue':0, 'drop':False}, # uncapped
       {'priority':600,'EthSrc':'00:00:00:00:00:04','EthDst':'00:00:00:00:00:01', 'queue':None, 'drop':False}, # uncapped

       {'priority':800,'EthSrc':'00:00:00:00:00:02','EthDst':'00:00:00:00:00:04', 'queue':1, 'drop':False}, # cap at 200 Mb/s

       {'priority':600,'EthSrc':'00:00:00:00:00:03','EthDst':'00:00:00:00:00:04', 'drop':True}, # blocked
       {'priority':600,'EthSrc':'00:00:00:00:00:04','EthDst':'00:00:00:00:00:03', 'drop':True}, # blocked

       {'priority':600,'EthSrc':'00:00:00:00:00:03','EthDst':'00:00:00:00:00:01', 'queue':None, 'drop':False}, # uncapped
       {'priority':600,'EthSrc':'00:00:00:00:00:02','EthDst':'00:00:00:00:00:01', 'queue':None, 'drop':False}, # uncapped
       {'priority':600,'EthSrc':'00:00:00:00:00:04','EthDst':'00:00:00:00:00:02', 'queue':0, 'drop':False}, # uncapped
        ]

def launch ():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn",  _handle_PacketIn)
    log.info("Switch running.")

def _handle_ConnectionUp ( event):
    log.info("Starting Switch %s", dpidToStr(event.dpid))
    msg = of.ofp_flow_mod(command = of.OFPFC_DELETE)
    event.connection.send(msg)


def _handle_PacketIn ( event): # Ths is the main class where your code goes, it will be called every time a packet is sent from the switch to the controller

    dpid = event.connection.dpid
    sw=dpidToStr(dpid)
    inport = event.port     # this records the port from which the packet entered the switch
    eth_packet = event.parsed # this parses the incoming message as an Ethernet packet
    log.debug("Event: switch %s port %s packet %s" % (sw, inport, eth_packet)) # this is the way you can add debugging information to your text

    table[(dpid,eth_packet.src)] = event.port   # this associates the given port with the sending node using the source address of the incoming packet
    dst_port = table.get((dpid,eth_packet.dst)) # if available in the table this line determines the destination port of the incoming packet

# this part is now separate from next part and deals with ARP messages

    ######################################################################################
    ############ CODE SHOULD ONLY BE ADDED BELOW  #################################

    if dst_port is None and eth_packet.type == eth.ARP_TYPE and eth_packet.dst == EthAddr(b"\xff\xff\xff\xff\xff\xff"): # this identifies that the packet is an ARP broadcast
        # => in this case you want to create a packet so that you can send the message as a broadcast
        msg = of.ofp_packet_out(data = event.ofp)
        event.connection.send(msg)

    for rule in rules: #now you are adding rules to the flow tables like before. First you check whether there is a rule match based on Eth source and destination
        if (eth_packet.dst==EthAddr(rule['EthDst']) and eth_packet.src==EthAddr(rule['EthSrc'])):
            log.debug("Event: found rule from source %s to dest  %s" % (eth_packet.src, eth_packet.dst))
            # => start creating a new flow rule for matching the ethernet source and destination
            msg = of.ofp_flow_mod()
            msg.priority = rule['priority']
            msg.match.dl_dst = rule['EthDst']
            msg.match.dl_src = rule['EthSrc']
            msg.hard_timeout = 400 # TODO: change back to 40 seconds for submission
            # soft timeout is not required for this exercise
            

            if (eth_packet.payload.protocol != 'TCP_PROTOCOL'):
                if (rule['drop']):
                    continue
                elif rule['queue' != None]:
                    msg.actions.append(of.ofp_action_enqueue(port = of.OFPP_ALL))
                else:
                    msg.actions.append(of.ofp_action_output(port = of.OFPP_ALL))
                
                event.connection.send(msg)

                msg = of.ofp_packet_out()
                msg.data = event.ofp
                msg.actions.append(of.ofp_action_output(port = of.OFFP_ALL))
                event.connection.send(msg)

            # => now check if the rule contains also TCP port info. If not install the flow without any port restriction
                # => also remember to check if this is a drop rule. The drop function can be added by not sending any action to the flow rule
                # => also remember that if there is a QoS requirement, then you need to use the of.ofp_action_enqueue() function, instead of the of.ofp_action_output
                # => and remember that in addition to creating a fow rule, you should also send out the message that came from the Switch
                # => at the end remember to send out both flow rule and packet

            else:
            # => otherwise:
                msg.match.dl_type = eth.IP_TYPE
                msg.match.nw_proto = ip.TCP_PROTOCOL
                msg.actions.append(of.ofp_action_output(port = rule['TCPPORT']))

            # => if the packet is an IP packet, its protocol is TCP, and the TCP port of the packet matches the TCP rule above
                # => add additioinal matching fields to the flow rule you are creating: IP-protocol type, TCP_protocol_type, destination TCP port.
                # => like above if it requires QoS then use the of.ofp_action_enqueue() function
                # => also remember to check if this is a drop rule.
                # => at the end remember to send out both flow rule and packet




    ########### THIS IS THE END OF THE AREA WHERE YOU NEED TO ADD CODE ##################################
    #####################################################################################################
            break
