import xbee
import struct

class XBee900HP(xbee.XBee):
    api_commands = {"at":
                    [{'name':'id',        'len':1,      'default':b'\x08'},
                     {'name':'frame_id',  'len':1,      'default':b'\x00'},
                     {'name':'command',   'len':2,      'default':None},
                     {'name':'parameter', 'len':None,   'default':None}],
                    "queued_at":
                        [{'name':'id',        'len':1,      'default':b'\x09'},
                         {'name':'frame_id',  'len':1,      'default':b'\x00'},
                         {'name':'command',   'len':2,      'default':None},
                         {'name':'parameter', 'len':None,   'default':None}],
                    "remote_at":
                        [{'name':'id',              'len':1,        'default':b'\x17'},
                         {'name':'frame_id',        'len':1,        'default':b'\x00'},
                         # dest_addr_long is 8 bytes (64 bits), so use an unsigned long long
                         {'name':'dest_addr_long',  'len':8,        'default':struct.pack('>Q', 0)},
                         {'name':'dest_addr',       'len':2,        'default':b'\xFF\xFE'},
                         {'name':'options',         'len':1,        'default':b'\x02'},
                         {'name':'command',         'len':2,        'default':None},
                         {'name':'parameter',       'len':None,     'default':None}],
                    "tx":
                        [{'name':'id',              'len':1,        'default':b'\x10'},
                         {'name':'frame_id',        'len':1,        'default':b'\x00'},
                         {'name':'dest_addr',       'len':8,        'default':b'\x000000000000ffff'},
                         {'name':'reserved',        'len':2,        'default':b'\xff\xfe'},
                         {'name':'radius',          'len':1,        'default':b'\x00'},
                         {'name':'options',         'len':1,        'default':b'\x00'},
                         {'name':'data',            'len':None,     'default':None}]
                    }

    tx_status_strings = {b'\x00': "success",
                         b'\x01': "MAC ACK failure",
                         b'\x02': "Collision Avoidance Failure",
                         b'\x21': "Network ACK Failure",
                         b'\x25': "Route Not Found",
                         b'\x31': "Internal Resource Error",
                         b'\x32': "Internal Error",
                         b'\x74': "Payload too large.",
                         b'\x75': "Indirect message unrequested."}

    api_responses = {b"\x90":
                        {'name':'rx',
                         'structure':
                            [{'name':'source_addr', 'len':8},
                             {'name':'reserved', 'len':2},
                             {'name':'options',     'len':1},
                             {'name':'rf_data',     'len':None}]},
                     b"\x82":
                        {'name':'rx_io_data_long_addr',
                         'structure':
                            [{'name':'source_addr_long','len':8},
                             {'name':'rssi',            'len':1},
                             {'name':'options',         'len':1},
                             {'name':'samples',         'len':None}],
                         'parsing': [('samples',
                                      lambda xbee,original: xbee._parse_samples(original['samples'])
                                     )]},
                     b"\x83":
                        {'name':'rx_io_data',
                         'structure':
                            [{'name':'source_addr', 'len':2},
                             {'name':'rssi',        'len':1},
                             {'name':'options',     'len':1},
                             {'name':'samples',     'len':None}],
                         'parsing': [('samples',
                                      lambda xbee,original: xbee._parse_samples(original['samples'])
                                     )]},
                     b"\x8b":
                        {'name':'tx_status',
                         'structure':
                            [{'name':'frame_id',    'len':1},
                             {'name':'reserved',    'len':2},
                             {'name':'retries',     'len':1},
                             {'name':'status',      'len':1},
                             {'name':'disco_status','len':1}]},
                     b"\x8a":
                        {'name':'status',
                         'structure':
                            [{'name':'status',      'len':1}]},
                     b"\x88":
                        {'name':'at_response',
                         'structure':
                            [{'name':'frame_id',    'len':1},
                             {'name':'command',     'len':2},
                             {'name':'status',      'len':1},
                             {'name':'parameter',   'len':None}],
                         'parsing': [('parameter',
                                       lambda xbee,original: xbee._parse_IS_at_response(original))]
                             },
                     b"\x97":
                        {'name':'remote_at_response',
                         'structure':
                            [{'name':'frame_id',        'len':1},
                             {'name':'source_addr_long','len':8},
                             {'name':'source_addr',     'len':2},
                             {'name':'command',         'len':2},
                             {'name':'status',          'len':1},
                             {'name':'parameter',       'len':None}],
                         'parsing': [('parameter',
                                       lambda xbee,original: xbee._parse_IS_at_response(original))]
                             },
                     }
