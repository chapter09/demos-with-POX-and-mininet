# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""
import string
from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.packet.ethernet import ethernet
from pox.lib.util import dpid_to_str

log = core.getLogger()

#ROUTE_TABLE = { 
#  3: {
#    '10.0.1.*': (),
#    '10.0.2.*': (),
#  },
#  4: {
#    '10.0.1.*': (),
#    '10.0.2.*': (),
#  },
#}

SUBNET = {3: '10.0.1.1', 4: '10.0.2.1'}

ROUTE_TABLE = {
    3: {'10.0.2.*': ('10.0.2.1', 3)},
    4: {'10.0.1.*': ('10.0.1.1', 1)},
    }


class Tutorial (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}
    self.ip_to_mac = {}

  def resend_packet (self, packet_in, out_port):
    """
    Instructs the switch to resend a packet that it had sent to us.
    "packet_in" is the ofp_packet_in object the switch had sent to the
    controller due to a table-miss.
    """
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)


  def arp_handler(self, packet, packet_in):
    if packet.payload.opcode == pkt.arp.REQUEST: 
      #if packet.payload.protodst == :
      #  arp_reply = arp()
      #  arp_reply.hwsrc = 
      #  arp_reply.hwdst = packet.src
      #  arp_reply.opcode = arp.REPLY
      #  arp_reply.protosrc = 
      #  arp_reply.protodst = packet.payload.protosrc

      #self.resend_packet(packet_in, of.OFPP_ALL)
      
      print 'DPID: ', self.connection.dpid
      print 'IN PORT: ', packet_in.in_port
      print packet.dst
      print packet.payload.protosrc
      print packet.payload.protodst
      print packet.payload.hwdst
      print packet.payload.hwsrc


      print packet

  def act_like_router(self, packet, packet_in):
    print "###start work as router###"
    print dpid_to_str(self.connection.dpid)


    ip = packet.find('ipv4')

    if not self.mac_to_port.has_key(packet.src):
      self.mac_to_port[packet.src] = packet_in.in_port

    if self.mac_to_port.has_key(packet.dst):
      out_port = self.mac_to_port[packet.dst]
      self.resend_packet(packet_in, out_port)

      msg = of.ofp_flow_mod()
      msg.match.dl_src = packet.dst
      msg.actions.append(of.ofp_action_output(port = out_port))
      self.connection.send(msg)

    elif ip and ip.srcip.startswith('10.0.2'):
      arp_req = arp()
      arp_req.hwsrc = string.replace(\
          dpid_to_str(self.connection.dpid),\
          '-', ':')
      arp_req.hwdst = ethernet.ETHER_BRAODCAST 
      arp_req.opcode = arp.REQUEST
      arp_req.protosrc = SUBNET[self.connection.dpid]
      arp_req.protodst = packet.payload.protosrc
      ether = ethernet()
      ether.type = ethernet.ARP_TYPE
      ether.dst = packet.src
      ether.src = dpid_to_str(self.connection.dpid)
      ether.payload = arp_req

      msg = of.ofp_packet_out()
      msg.data = ether.pack()
      msg.actions.append(of.ofp_action_output(port = packet_in.in_port))
      self.connection.send(msg)

      packet.dst = ''


      


    if packet.type == ethernet.ARP_TYPE:
      if packet.payload.opcode == pkt.arp.REQUEST: 
        
        if not self.ip_to_mac.has_key(packet.payload.protosrc):
          self.ip_to_mac[packet.payload.protosrc] = packet.payload.hwsrc

        if packet.payload.protodst == SUBNET[self.connection.dpid]:
          arp_reply = arp()
          arp_reply.hwsrc = string.replace(\
              dpid_to_str(self.connection.dpid),\
              '-', ':')
          arp_reply.hwdst = packet.src
          arp_reply.opcode = arp.REPLY
          arp_reply.protosrc = SUBNET[self.connection.dpid]
          arp_reply.protodst = packet.payload.protosrc
          ether = ethernet()
          ether.type = ethernet.ARP_TYPE
          ether.dst = packet.src
          ether.src = dpid_to_str(self.connection.dpid)
          ether.payload = arp_reply

          msg = of.ofp_packet_out()
          msg.data = ether.pack()
          msg.actions.append(of.ofp_action_output(port = packet_in.in_port))
          self.connection.send(msg)

        else:
          msg = of.ofp_packet_out()
          msg.data = packet_in

          # Add an action to send to the specified port
          if self.connection.dpid == 3: 
            msg.actions.append(of.ofp_action_output(port = 1))
            msg.actions.append(of.ofp_action_output(port = 2))
          elif self.connection.dpid ==4:
            msg.actions.append(of.ofp_action_output(port = 2))

          # Send message to switch
          self.connection.send(msg)






    #  ip_packet = packet.payload
    #  if ip_packet.protocol == pkt.ICMP:
    #    icmp_packet = ip_packet.payload
    #    print ip_packet
    
    #ip = packet.find('ipv4')
    #if ip:
    #  dstip = ip.dstip
    #  log.debug("%s"%dstip)




  def _handle_PacketIn(self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # Comment out the following line and uncomment the one after
    # when starting the exercise.
    # self.act_like_hub(packet, packet_in)
    # self.act_like_switch(packet, packet_in)
    self.act_like_router(packet, packet_in)


def launch():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
