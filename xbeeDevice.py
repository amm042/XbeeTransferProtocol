#from xbee import XBee

import threading
import serial
import time
import logging
import struct
import datetime

import traceback

from xbee import XBee as XBeeS1
from xb900hp import XBee900HP
class XBeeDied(Exception): pass

class XBeeDevice:
    MAX_TIMEOUTS = 6

    def __init__(self, portstr, rxcallback, xbeeclass, **kwargs):

        self._in_init = True
        self._portstr = portstr
        self._xbeeclass = xbeeclass

        self.log = logging.getLogger(__name__)
        self.reset_rssi()

        self._rxcallback = rxcallback
        self._next_frame_id = 1
        self._max_packets = 3

        self._timeout = datetime.timedelta(seconds=1)
        self._lastrssi = datetime.datetime.now()

        # params read from the radio
        self.xch = 0
        self.xmm = 0
        self.xid = 0
        self.address = 0

        if 'pl' in kwargs:
            self.pl = kwargs['pl']
        else:
            self.pl = 0

        self.mtu = 100 #series 1 doesn't support NP, and is always 100
        self.on_energy = None

        try:
            self._mkxbee()
        except Exception as x:
            self.close()
            raise x
        if 'xbeeCM' in kwargs and self._xbeeclass == XBee900HP:
            self.send_cmd("at", command=b'CM',
                parameter= struct.pack(">Q", kwargs['xbeeCM']))
            self.send_cmd("at", command=b'CM')

        self._in_init = False


    def _mkxbee(self):

        self._pending = {}

        self._lock = threading.Lock()

        # initialize to something reasonable
        self._last_sendwait_length = datetime.timedelta(milliseconds=50)
        self._timeout_err_cnt = 0
        self._idle = threading.Event()

        self._channel_mask = 0
        self._channel_cache= {}

        self.log.debug("Opening serial: " + self._portstr)
        dev, baud, opts = self._portstr.split(":")
        self._serial = serial.Serial(dev, baudrate=int(baud),
                                     bytesize=int(opts[0]),
                                     parity=opts[1],
                                     stopbits=int(opts[2]),
                                     rtscts = True)
        self._xbee = self._xbeeclass(self._serial, escaped=True,
                          callback=self._on_rx,
                          error_callback = self._on_error)

        self._addrlen=2
        for part in self._xbee.api_commands['tx']:
            if part['name'] == 'dest_addr':
                self._addrlen = part['len']

        # remove this to use default power level.
        self.log.warn("Check power levels!!!!!")
        self.send_cmd("at", command=b'PL',
                      parameter=struct.pack("B", self.pl))
        self.send_cmd("at", command=b'PL')

        # self.send_cmd("at", command=b'PM', parameter=b'\x01')
        # self.send_cmd("at", command=b'PM')

        # point to multipoint
        if self._xbeeclass == XBee900HP:
            self.send_cmd("at", command=b'TO', parameter=b'\x40')
            self.send_cmd("at", command=b'CM')

       # read addresses
        if self._addrlen == 2:
            self.send_cmd("at", command=b"MY")
        elif self._addrlen == 8:
            self.send_cmd("at", command=b'SL')
            self.send_cmd("at", command=b'SH')

        # read channel and PAN id
        self.send_cmd("at", command=b'CH')
        self.send_cmd("at", command=b'ID')
        self.send_cmd("at", command=b'MM')

        #self.send_cmd("at", command=b'NP')
        self.flush()

    def flush(self):
        if not self._idle.wait(self._timeout.total_seconds()):

            try:
                self._lock.acquire()
                self._timeout_err_cnt += 1

                # drop anything we migth be waiting for
                self._pending = {}
                self._idle.set()

                if self._timeout_err_cnt > XBeeDevice.MAX_TIMEOUTS:
                    raise XBeeDied("flush with too many timeouts")
                raise TimeoutError("Flush timeout.")
            finally:
                self._lock.release()
        self._timeout_err_cnt = 0

    def sendwait(self, data=None, atcmd = 'tx',
                 timeout = None,
                 **kwargs):
        'send the message and wait for the result'
        begin = datetime.datetime.now()

        # may raise timeouterror
        self.flush()

        e = self.send(data=data, atcmd=atcmd, **kwargs)
        if timeout == None:
            timeout = self._timeout.total_seconds()
        if not e.wait(timeout):
            try:
                self._lock.acquire()
                self._timeout_err_cnt += 1
                if self._timeout_err_cnt > XBeeDevice.MAX_TIMEOUTS:
                    raise XBeeDied("sendwait too many timeouts")

                if e.fid in self._pending:
                    del self._pending[e.fid]
                else:
                    self.log.error("sendwait timeout, but no matching frame id {}".format(e.fid))

                raise TimeoutError("Timeout sending message")
            finally:
                self._lock.release()
        self._timeout_err_cnt = 0
        end = datetime.datetime.now()
        self._last_sendwait_length = end-begin
        return e.pkt

    def send(self, data=None, dest= 0xffff, atcmd='tx', **kwargs):
        'format and send a data packet, default to broadcast'

        if ('mm' in kwargs and kwargs['mm'] != self.xmm):
            # switch mac mode
            self.log.debug("{}: Change MAC mode {} --> {}".format(
                self._portstr,
                self.xmm,
                kwargs['mm']
            ))
            self.send_cmd("at", command=b'MM', parameter=kwargs['mm'])
            #self.send_cmd("at", command=b'MM')
            # assume it works to avoid having to ask the radio for mm
            self.xmm = kwargs['mm']
        if self._addrlen == 2:
            return self.send_cmd(cmd=atcmd,
                                 dest_addr=struct.pack(">H", dest),
                                 data=data, **kwargs)
        elif self._addrlen == 8:
            return self.send_cmd(cmd=atcmd,
                                 dest_addr=struct.pack(">Q", dest),
                                 data=data, **kwargs)
        else:
            raise Exception("Unsupported address length")


    def send_cmd(self, cmd, **kwargs):
        begin = datetime.datetime.now()
        while len(self._pending) > self._max_packets:
            if datetime.datetime.now() - begin > self._timeout:
                raise TimeoutError("Tx overrun -- are packets going out?")
            time.sleep(0.05)

        e = threading.Event()
        if 'ack' not in kwargs or kwargs['ack'] == True:
            self._idle.clear()
            fid = struct.pack("B", self._next_frame_id)
        else:
            # frame id 0 is non acked
            fid = b'\x00'

        try:
            self._lock.acquire()
            self._pending[fid] = e
        finally:
            self._lock.release()

        e.fid = fid

        pkt=dict(kwargs)
        pkt['id'] = cmd
        #print(pkt)
        self.log.debug("xbee tx [{:x}, pid={}, fid={}]: {}".format(self.address,
                                                                   pkt['id'], fid, pkt))

        self._xbee.send(cmd, frame_id = fid, **kwargs)

        if 'ack' not in kwargs or kwargs['ack'] == True:
            self._next_frame_id += 1
            if self._next_frame_id > 0xff:
                self._next_frame_id = 1
        else:
            e.set()

        return e

    def _on_error(self, error):
        self.log.error('Failed with: {}'.format(str(error)))
        self.log.error(traceback.format_exc())

        raise XBeeDied(error)
        # raise XBeeDied?

        #
        # try:
        #     self._serial.close()
        # except:
        #     pass
        #
        # self._xbee = None
        # self._serial = None
        #
        # # reload xbee
        # if self._in_init == False:
        #     try:
        #         self._mkxbee()
        #     except Exception as x:
        #         raise x

    def freq_to_maskbit(self, freq):
        atfreq = 902.4

        step = 0.4
        max = atfreq + step * 64
        i = 1

        while abs(atfreq - freq) > 0.01 and atfreq < max:
             atfreq += step
             i <<= 1

        return i

    def channel_to_freq(self, i):

        if i in self._channel_cache:
            return self._channel_cache[i]

        # return the ith enabled bit in the channel mask
        freq = 902.4
        step = 0.4
        cm = self._channel_mask
        cnt = 0

        # find first freq
        while cm & 0x1 == 0x0:
            freq+=step
            cm >>= 1

        self._channel_cache[cnt] = freq

        while i > 0:
            cnt += 1
            i-=1
            freq+=step
            cm >>= 1
            # check if new channel is disabled
            while cm & 0x1 == 0x0:
                freq+=step
                cm >>= 1
            self._channel_cache[cnt] = freq

        return freq
    def avg_rssi(self):
        if len(self.rssi_history) > 0:
            frssi = list(filter(lambda x: x!=0, self.rssi_history))
            if len(frssi) > 0:
                return sum(frssi)/len(frssi)
            else:
                return 0
        else:
            return 0
    def _on_rx(self, pkt):
        self.log.debug("xbee rx [{:x}, {}]: {}".format(self.address, pkt['id'], pkt))

        if 'rssi' in pkt:
            self.rssi_history.append(-struct.unpack("B", pkt['rssi'])[0])

        try:
            self._lock.acquire()

            if 'frame_id' in pkt and pkt['frame_id'] in self._pending:
                self._pending[pkt['frame_id']].pkt = pkt
                self._pending[pkt['frame_id']].set()
                del self._pending[pkt['frame_id']]

            if len(self._pending) == 0:
                self._idle.set()
        finally:
            self._lock.release()

        if pkt['id'] == 'tx_status':
            if pkt['status'] != b'\x00':
                s = pkt['status']
                if s in XBee900HP.tx_status_strings:
                    self.log.warn("unsuccessful tx: {}".format(XBee900HP.tx_status_strings[s]))
                else:
                    self.log.warn("unsuccessful tx: {}".format(s))

        if pkt['id'] == 'at_response':
            if 'status' in pkt and pkt['status'] > b'\x00':
                self.log.warn("At command failed: {}".format(pkt))

            if pkt['command'] == b'SL':
                if 'parameter' in pkt:
                    self.address = (0xffffffff00000000 & self.address) | (struct.unpack('>L', pkt['parameter'])[0])
            elif pkt['command'] == b'MM':
                if 'parameter' in pkt:
                    self.xmm = pkt['parameter']
                    self.log.debug("{}: MAC mode = {}".format(
                        self._portstr,
                        self.xmm))

            elif pkt['command'] == b'TO':
                pass
            elif pkt['command'] == b'CH':
                if 'parameter' in pkt:
                    self.xch = struct.unpack(">B", pkt['parameter'])[0]
                    self.log.info("{}: Channel = {} ({} MHz)".format(
                        self._portstr,
                        self.xch,
                        2405.0 + (self.xch - 11) * 5))
            elif pkt['command'] == b'ID':
                if 'parameter' in pkt:
                    self.log.info("{}: PAN ID = {}".format(
                        self._portstr,
                        pkt['parameter']))
            elif pkt['command'] == b'SH':
                if 'parameter' in pkt:
                    self.address = (0x00000000ffffffff & self.address) | (struct.unpack('>L', pkt['parameter'])[0] << 32)
            elif pkt['command'] == b'MY':
                if 'parameter' in pkt:
                    self.address = struct.unpack (">H", pkt['parameter'])[0]
            elif pkt['command'] == b'DB':

                if pkt['parameter'][0] != 0:
                    #self.rssi_history.pop(0)
                    self.rssi_history.append(-pkt['parameter'][0])

                    #self.log.info("RSSI -{}dBm {}".format(pkt['parameter'][0], self.rssi_history ))

            elif pkt['command'] == b'NP':
                self.log.info("NP Resp: {}".format(pkt))
                if 'parameter' in pkt:
                    self.mtu = pkt['parameter'][0]
            elif pkt['command'] == b'PL':
                if 'parameter' in pkt:
                    pwr = struct.unpack(">B", pkt['parameter'])[0]
                    # this is for series 2...
                    # if pwr == 0:
                    #     pwr_str = "-5 dBm"
                    # elif pwr == 1:
                    #     pwr_str = "-1 dBm"
                    # elif pwr == 2:
                    #     pwr_str = "1 dBm"
                    # elif pwr == 3:
                    #     pwr_str = "3 dBm"
                    # elif pwr == 4:
                    #     pwr_str = "5 dBm"
                    # else:
                    #     pwr_str = "{} (unknown/unsupported dBm)".format(pwr)

                    self.log.info("Power Level: {}".format(pwr))
                else:
                    self.log.info("PL set.")
            elif pkt['command'] == b'PM':
                if 'parameter' in pkt:
                    boost = struct.unpack(">B", pkt['parameter'])[0]
                    if boost == 1:
                        self.log.info("Power boost on (+2 dBm rx, +3 dBm tx).")
                    elif boost == 0:
                        self.log.info("Power boost off.")
                    else:
                        self.log.info("Power boost unknown/unsupported ({}).".format(boost))
                else:
                    self.log.info("PM set.")
            elif pkt['command'] == b'FN':
                self.log.info("Neighbor info: {}".format(pkt['rf_data'].decode('utf-8')))
            elif pkt['command'] == b'ND':
                self.log.info("Network info: {}".format(pkt['rf_data'].decode('utf-8')))
            elif pkt['command'] == b'CM':
                # mask is sent as a hex string of varying length....
                if 'parameter' in pkt:
                    self._channel_cache ={}
                    self._channel_mask = int("".join(["{:02x}".format(i) for i in pkt['parameter']]),16)
                    self.log.info("Channel mask is {:x}".format(self._channel_mask))
            elif pkt['command'] == b'ED':
                for i,d in enumerate(pkt['parameter']):
                    self.log.info("Energy info [{:02d} = {:3.2f} MHz]: -{}dBm".format(i, self.channel_to_freq(i), d))

                if self.on_energy != None:
                    self.on_energy (self, [(self.channel_to_freq(i), d) for i,d in enumerate(pkt['parameter'])])
            elif pkt['command'] == b'MM':
                mac_modes = {
                    b'\x00':'Digi + header',
                    b'\x01':'802.15.4 (no ACKs)',
                    b'\x02':'802.15.4 (with ACKs)',
                    b'\x03':'Digi (no ACKs)'
                }
                if 'parameter' in pkt:
                    self.log.info("MAC Mode: {}".format(
                        mac_modes[pkt['status']] if pkt['parameter'] in mac_modes else "Unknown"
                    ))
                else:
                    self.log.info("MAC Mode change {}.".format(
                        "success" if pkt['status'] == b'\x00' else "error "+pkt['status'].decode('utf-8')
                    ))
            else:
                self.log.warn("Unsupported command response: {}:{}".format(pkt['command'], pkt))
        if pkt['id'] == 'rx':


            # if (
            #     (sum(self.rssi_history) == 0) and (datetime.datetime.now() - self._lastrssi > datetime.timedelta(seconds=0.1)) or
            #     (datetime.datetime.now() - self._lastrssi > datetime.timedelta(seconds=5))
            #     ):
            #     # poll rssi
            #     # disable for testing....
            #     # self.send_cmd("at", command=b'DB')
            #     self._lastrssi = datetime.datetime.now()

            srcaddr = None
            if self._addrlen == 2:
                srcaddr = struct.unpack(">H", pkt['source_addr'])[0]
            elif self._addrlen == 8:
                srcaddr = struct.unpack(">Q", pkt['source_addr'])[0]
            else:
                raise Exception("Unsupported address length")

            self._rxcallback(self,
                             srcaddr,
                             pkt['rf_data'])

    def reset_rssi(self):
        self.rssi_history = []
    def get_rssi(self):
        self.send_cmd("at", command=b'DB')
        self._lastrssi = datetime.datetime.now()
    def close(self):
        self._xbee.halt()
        self._serial.close()
