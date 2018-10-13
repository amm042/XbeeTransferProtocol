from xbeeDevice import XBeeDevice
import zlib
import fragmentation16 as frag
import logging
import sys
import os
import os.path
import logging.handlers
import hexdump
import time
import datetime
import threading
from bitarray import bitarray
import struct
import argparse
import math
from xTP import xTP, md5file
from xbee import XBee as XBeeS1
from xb900hp import XBee900HP

class NoRemoteException(Exception):pass

class XTPClient():
    def rx(self, xbeedev, srcaddr, data):
        self.last_activity = datetime.datetime.now()
        logging.debug("RX [{:x}<-{:x}]: {} -- {}".format(self.xbee.address,
                                                            srcaddr,
                                                     data,
                                                     hexdump.dump(data)))

        if data[0:1] in self.have_response:
            self.have_response[data[0:1]]['rsp'] = (srcaddr, data)
            self.have_response[data[0:1]]['e'].set()
        elif data[0:1] == xTP.HELLO:
            self.remote = srcaddr
            self.have_remote.set()
        elif data[0:1] == xTP.SEND32_BEGIN:
            self.begin_transfer.set()
        elif data[0:1] == xTP.SEND32_ACKS:
            l = struct.unpack(">L", data[1:5])[0]
            self.acks = bitarray()
            self.acks.setall(0)
            self.acks.frombytes(data[5:])
            # mark extra bits as received so all() works
            for z in range(l, len(self.acks)):
                self.acks[z] = True
            logging.debug("mask is [{}]: {}".format( l, self.acks ))

            self.have_acks.set()
        else:
            logging.warn("RX -- unknown message format ({:x})".format(data[0]))


    def __init__(self, portstr, xbeeclass):
        self.xbee = XBeeDevice(portstr, self.rx, xbeeclass)
        #self.xbee.send_cmd("at", command=b'MY', parameter=b'\x16\x16')

        logging.info("my address: {:x}".format(self.xbee.address))
        logging.info("MTU: {} bytes".format(self.xbee.mtu))

        self.remote = None
        self.have_remote = threading.Event()
        self.begin_transfer = threading.Event()
        self.have_acks = threading.Event()
        self.have_response = {}
        self.retries = 15

        # testing
        #self.remote = 0x1616
        #self.have_remote.set()

        # mode 1 = 802.15.4 NO ACKs
        self.xbee.send_cmd("at", command=b'MM', parameter=b'\x01')
        self.xbee.send_cmd("at", command=b'MM')

        self.last_activity = datetime.datetime.now()
        self.beacon_time = datetime.timedelta(seconds=1)

        self.remote_timeout = datetime.timedelta(seconds=16)

    def send(self, data, remote_filename, filesize, offset = 0, dest=0xffff):
        "send with fragmentation, returns true on success"

        start = datetime.datetime.now()
        self.last_activity = datetime.datetime.now()

        # mtu seems imprecise. (does not include headers)
        frags = list(frag.make_frags(data, threshold=self.xbee.mtu - 8, encode = False))

        assert len(frags)< 2**16, "Using 16-bit frag counter, too many fragments. Chunk size is too big!"

        self.xbee.reset_rssi()
        self.begin_transfer.clear()
        self.have_acks.clear()
        ok_begin = False

        stats = {
            'control_pkt': 0,
            'control_bytes': 0,
            'frag_pkt': 0,
            'frag_bytes': 0,
            'frag_nack': 0,
            'frag_total': len(frags),
            'frag_total_bytes': len(data)
        }

        for i in range(self.retries):
            msg = xTP.SEND32_REQ + struct.pack(">LLLL",
                              offset, filesize, frags[0].total, frags[0].crc) + \
                              remote_filename.encode("utf-8")

            logging.debug("TX SEND32_REQ {}/{} [{:x}->{:x}]: {}".format(i, self.retries,
                                    self.xbee.address,
                                    dest,
                                    hexdump.dump(msg)))

            stats['control_pkt'] += 1
            stats['control_bytes'] += len(msg)

            # send the request to begin a transfer
            try:
                self.xbee.sendwait(data=msg, dest=dest, mm=b'\x02')
            except TimeoutError:
                continue

            if (self.begin_transfer.wait(self.xbee._timeout.total_seconds())):
                self.xbee.get_rssi()
                logging.debug("Begin transfer at {} of {} for file {}, ({} fragments).".format(
                    offset, filesize, remote_filename,
                    frags[0].total
                    ))
                ok_begin = True
                break
            else:
                self.xbee.get_rssi()
                logging.info("Failed to begin transfer.")
                return False, stats

        if ok_begin == False:
            return False, stats

        #initial set of acks
        self.acks = bitarray(len(frags))
        self.acks.setall(0)
        for j in range(self.retries):
            txcnt = 0
            for i,f in enumerate(frags):
                if self.acks[i] == False:
                    txcnt += 1
                    d = xTP.SEND32_DATA + struct.pack(">H", i) + f.data
                    e = self.xbee.send(data=d,
                                       dest=dest,
                                       mm=b'\x01')

                    stats['frag_pkt'] += 1
                    stats['frag_bytes'] += len(d)

                    logging.debug("TX SEND32_DATA {}/{} [{:x}->{:x}][{}]: {}".format(i, len(frags),
                                            self.xbee.address,
                                            dest,
                                            e.fid, hexdump.dump(d)))
            if txcnt == 0:
                logging.warn("TX complete due to no packets to send")
                return True, stats # must have worked.
            else:
                logging.debug("Sent {} fragments".format(txcnt))
            # block until all packets go out...
            self.xbee.flush()

            got_acks = False
            for k in range(self.retries):
                self.xbee.get_rssi()

                msg = xTP.SEND32_GETACKS
                self.have_acks.clear()

                logging.debug("TX SEND32_GETACKS {}/{} [{:x}->{:x}][{}]: {}".format(k, self.retries,
                                        self.xbee.address,
                                        dest,
                                        e.fid, hexdump.dump(msg)))
                stats['control_pkt'] += 1
                stats['control_bytes'] += len(msg)

                try:
                    self.xbee.sendwait(data=msg, dest=dest, mm=b'\x02')
                except TimeoutError:
                    continue

                if self.have_acks.wait(self.xbee._timeout.total_seconds()):
                    stats['frag_nack'] += len(self.acks) - self.acks.count()

                    logging.debug("Got acks. [{} of {}]".format(
                        self.acks.count(),
                        self.acks.length()))
                    got_acks = True
                    tm = datetime.datetime.now() - start
                    if self.acks.all():
                        logging.debug("Finish transfer at {} of {} for file {} in {} = {:.2f} kbps, avg_rssi = {:.2f} dBm.".format(
                                offset, filesize, remote_filename, tm, (8*len(data)/1024) / tm.total_seconds(),
                                self.xbee.avg_rssi()))
                        return True, stats
                    break

            if got_acks == False:
                logging.warn("Failed because remote didn't send acks.")
                return False, stats


        return False, stats

    def send_file(self, filename,
                  remote_filename = None,
                  chunk_size = 8*1024):
        if remote_filename == None:
            remote_filename = filename

        filestats = {
            'control_pkt': 0,
            'control_bytes': 0,
            'chunks_total': 0,
            'chunks_sent': 0,
            'frag_pkt': 0,
            'frag_nack': 0,
            'frag_bytes': 0,
            'frag_total': 0,
            'frag_total_bytes': 0
        }

        if os.path.exists(filename):
            if not self.have_remote.wait(timeout=0):
                logging.info("Waiting for remote side.")
                if not self.have_remote.wait(self.remote_timeout.total_seconds()):
                    raise NoRemoteException("No remote server detected.")

            pos = 0
            chunknum = 0
            fsize = os.stat(filename).st_size

            with open(filename, 'rb') as f:
                while pos == 0 or len(data) > 0:
                    chunknum += 1
                    data = f.read(chunk_size)

                    if len(data) > 0:
                        filestats['chunks_total'] += 1

                        logging.info("Sending chunk {} of {} for file {} using {} byte chunks, avg rssi {} dBm.".format(
                            chunknum,
                            math.ceil(fsize/chunk_size),
                            filename,
                            chunk_size,
                            self.xbee.avg_rssi()
                            ))

                        success = False
                        for i in range(self.retries):
                            filestats['chunks_sent'] += 1
                            result, stats = self.send(data=data,
                                  remote_filename=remote_filename,
                                  offset = pos,
                                  filesize= os.path.getsize(filename),
                                  dest=self.remote)

                            # sum stats onto filestats.
                            for k,v in stats.items():
                                filestats[k] += v

                            if (result):
                                pos += len(data)
                                success = True
                                break
                            logging.warn("Retry chunk.")
                        if success == False:
                            return False, filestats

            return success, filestats
    def send_pkt_retry(self, msg, waitfor_msg):
        self.have_response[waitfor_msg] = {'e': threading.Event(), 'rsp': None}
        for i in range(self.retries):

            logging.debug("TX -{:02x}- {}/{} [{:x}->{:x}]: {}".format(msg[0], i, self.retries,
                                    self.xbee.address,
                                    self.remote,
                                    hexdump.dump(msg)))

            try:
                self.xbee.sendwait(data=msg, dest=self.remote, mm=b'\x02')
            except TimeoutError:
                continue
            if self.have_response[waitfor_msg]['e'].wait(self.xbee._timeout.total_seconds()):
                return self.have_response[waitfor_msg]['rsp']

        return None, None

    def verify(self, filename,  remote_filename = None):
        if remote_filename == None:
            remote_filename = filename
        if os.path.exists(filename):
            if not self.have_remote.wait(timeout=0):
                logging.info("Waiting for remote side.")
                if not self.have_remote.wait(self.remote_timeout.total_seconds()):
                    raise NoRemoteException("No remote server detected.")

            d = md5file(filename)

            logging.debug("digest of {} is: [{}]: {}".format(filename, len(d),d))

            msg = xTP.MD5_CHECK + d + 16*b'\x00' + remote_filename.encode("utf-8")
            addr, rsp = self.send_pkt_retry(msg, xTP.MD5_CHECK)

            if rsp == None:
                return None

            lhash = rsp[1:17]
            rhash = rsp[17:33]
            logging.debug("response local: {} remote: {}".format(lhash, rhash))
            return lhash == rhash


if __name__ == "__main__":
    # run the Client

    p = argparse.ArgumentParser()

    p.add_argument("portstr", help="pylink style port string eg: /dev/ttyUSB0:38400:8N1")
    p.add_argument("file", help="file(s) to send", nargs='+')
    p.add_argument("-d", "--debug", help="logging debug level",
                    choices=['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL'], default = 'INFO')
    p.add_argument("-x", "--xbee", help="XBee variant",
                    choices=['S1', '900HP'], default='S1')
    xcls = {'S1': XBeeS1, '900HP': XBee900HP}

    args = p.parse_args()
    logfile = os.path.splitext(os.path.basename(sys.argv[0]))[0] + ".log"
    logging.basicConfig(level=logging.getLevelName(args.debug),
                    handlers=(logging.StreamHandler(sys.stdout),
                              logging.handlers.RotatingFileHandler(logfile,
                                                                    maxBytes = 256*1024,
                                                                    backupCount = 0), ),
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    xtp = None
    try:
        xtp = XTPClient(args.portstr, xcls[args.xbee])

        time.sleep(0.5)
        for filename in args.file:
            logging.info("Sending {}".format(filename))

            start = datetime.datetime.now()

            if xtp.send_file(filename):
                result = xtp.verify(filename)
                t = (datetime.datetime.now() - start).total_seconds()
                sz = os.path.getsize(filename)
                logging.info("Sent {} verified={}, {:.2f} kbps.".format(filename, result,
                                                              (8*sz/1024)/t))
            else:
                logging.info("Sent {} failed.".format(filename))
    finally:
        if xtp != None:
            xtp.xbee.close()
