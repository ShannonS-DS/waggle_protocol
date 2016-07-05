#!/usr/bin/python3

# packetmaker.py
"""
    This module contains a few utilities that autogenerate complete simple packets,
    such as ping and time request packets.
"""
from gPickler import gPickle
import sys, os, os.path
sys.path.append("..")
sys.path.append("../..")
from waggle_protocol.protocol.PacketHandler import *

# Dictionary of supported fuctions
func_dict = {('p', 'r'): (make_ping_packet, ('s_puid', 'r_puid')),
             ('t', 'r'): (make_time_packet, ('s_puid', 'r_puid')),
             ('s', 'd'): (make_data_packet, ('data', 'sender', 'recipient')),
             ('r', 'r'): (registration_packet, ('meta')),
             ('r', 'n'): (make_config_reg, ('meta')),
             ('r', 'd'): (deregistration_packet, ('rec'))}

def make_ping_packet(s_puid="", r_puid=""):
    """
        Returns a simple ping request packet.
        
        :param sender: hex string puid of the sender
        :param recipient: hex string puid of the recipient
        :rtype: string
    """
    header_dict = {
        "msg_mj_type" : ord('p'),
        "msg_mi_type" : ord('r')
    }
    return pack(header_dict, s_puid=s_puid, r_puid=r_puid)

def make_time_packet(s_puid="", r_puid=""):
    """
        Returns a simple time request packet.

        :param sender: hex string puid of the sender
        :param recipient: hex string puid of the recipient
        :rtype: string
    """
    header_dict = {
        "msg_mj_type" : ord('t'),
        "msg_mi_type" : ord('r')
    }
    return pack(header_dict, s_puid=s_puid, r_puid=r_puid)

def make_data_packet(data, s_puid="", r_puid=""):
    """
    Compresses sensor data and returns a sensor data packet. 

    :param args: data, puid (optional)
    :rtype: string 
    """ 
    msg = gPickle(args['data'])

    header_dict = {
        "msg_mj_type" : ord('s'),
        "msg_mi_type" : ord('d')
        }
    return pack(header_dict, message_data = msg, s_puid=s_puid, r_puid=r_puid)

def registration_packet(meta):
    """
        Returns a registration request packet.

        :rtype: string
    """ 

    header_dict = {
        "msg_mj_type" : ord('r'),
        "msg_mi_type" : ord('r')
        }
    msg = str(meta)
        
    return pack(header_dict, message_data = msg)

def make_config_reg(config):
    """
        Returns a configuration registration packet. 
        
        :param config: node configuration file
        :rtype: string
        
    """
    header_dict = {
        "msg_mj_type" : ord('r'),
        "msg_mi_type" : ord('n')
        }
    return pack(header_dict, message_data = config)
    
def make_GN_reg(recp_ID):
    """
        Returns a guestnode registration packet to send to the node controller.
    """
    
    header_dict = {
        "msg_mj_type" : ord('r'),
        "msg_mi_type" : ord('r'),
        "r_uniqid" : recp_ID
        
        }
    

    return pack(header_dict, message_data = '')

#TODO may want to add an additional option argument to specify sender_id so that server can send a de-registration message for a GN
def deregistration_packet(recp_ID):
    """
        Returns a deregistration request packet.

        :param recp_ID: Unique ID of the message recipient
        :rtype: string
    """ 

    header_dict = {
        "msg_mj_type" : ord('r'),
        "msg_mi_type" : ord('d'),
        "r_uniqid" : recp_ID
        }
  
        
    return pack(header_dict, message_data = '')














