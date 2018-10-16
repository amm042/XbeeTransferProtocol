#!/usr/bin/env python3
from xTPListen import XTPServer
from xTPSend import XTPClient, NoRemoteException
from xbee import XBee as XBeeS1
from xbeeDevice import XBeeDied

from serial.tools import list_ports

import threading
import logging
import sys
from datetime import datetime, timezone

from pprint import pprint

from pymongo import MongoClient

import argparse

collect = MongoClient("mongodb://owner:Biethux7@eg-mongodb/amm042")['amm042']['xTBbenchmark']


def ok():
    user = '!'
    while not user in 'YyNn' and user != '':
        user = input("Ok? [Y/n]: ")

    return user in 'yY' or user == ''


def bench(send_dev = None, archive_path="./tmp", receive_dev=None, baud=38400, opts="8N1", **kwargs):
    "benchmark using given devices."

    if receive_dev:
        rx = XTPServer(
            "{}:{}:{}".format(receive_dev, baud, opts),
            archive_path,
            XBeeS1,
            **kwargs)

        # if also sending, run receive on a separate thread, else
        # receive runs on the main thread.
        if send_dev:
            rx_thread = threading.Thread(
                target=rx.run_forever,
                name="Bench Rx Thread")
            rx_thread.start()
        else:
            try:
                rx.run_forever()
            except KeyboardInterrupt:
                print("Ctrl-C, quit.")
                rx.stop()
                rx.xbee.close()
                return

    if send_dev:
        tx = XTPClient(
            "{}:{}:{}".format(send_dev, baud, opts),
            XBeeS1,
            **kwargs)

        #$ dd if=/dev/urandom of=test-1M.dat bs=1M count=1

        result = {}
        for tries in range(16):
            #for cs in [1,2,4,8,16,32,64]:
            for cs in [64,32,16,8,4,2,1]:

                testfile= 'test-1M.dat'
                chunksize = 1024*cs
                try:
                    start = datetime.now()
                    r, st = tx.send_file(testfile, chunk_size = chunksize)
                    end = datetime.now()
                    st['success'] = r
                    st['when'] = datetime.now(timezone.utc)
                    st['filename'] = testfile
                    st['chunksize'] = chunksize
                    if send_dev:
                        st['tx_rssi'] = tx.xbee.rssi_history
                    if receive_dev:
                        st['rx_rssi'] = rx.xbee.rssi_history
                    st['seconds'] = (end - start).total_seconds()
                    st['rate'] = st['frag_total_bytes'] / st['seconds']
                    collect.insert_one(st)

                except NoRemoteException:
                    print("No remote detected, skipping .")
                    if receive_dev and not rx_thread.isAlive():
                        print ("RX Died. Abort.")
                        try:
                            rx.stop()
                            rx_thread.join(timeout=1)
                            rx.xbee.close()
                            tx.xbee.close()
                        except:
                            pass

                        exit(-7)
                    continue
                except XBeeDied:
                    print("Xbee Died. Abort.")
                    try:
                        if receive_dev:
                            rx.stop()
                            rx_thread.join(timeout=1)
                            rx.xbee.close()
                        tx.xbee.close()
                    except:
                        pass

                    exit(-6)
                except KeyboardInterrupt:
                    print("Ctrl-C, exit")

                    try:
                        if receive_dev:
                            rx.stop()
                            rx_thread.join(timeout=1)
                            rx.xbee.close()
                        tx.xbee.close()
                    except:
                        pass

                    exit(-5)


                print (st)


    #
    # print("="*80)
    # for cs, r in result.items():
    #     print("-"*80)
    #     print("{}K".format(cs))
    #     print(", ".join(["{}".format(z[0]) for z in r]))
    #     print(", ".join(["{}".format(z[1]) for z in r]))
    #     print(", ".join(["{}".format(z[2]) for z in r]))

    if receive_dev:
        rx.stop()
        rx_thread.join()
        rx.xbee.close()
    if send_dev:
        tx.xbee.close()
    print("-"*80)

if __name__=="__main__":


    p = argparse.ArgumentParser()
    p.add_argument("-rxd", "--rx_device",
                   help="recieve device",
                   default = None)
    p.add_argument("-txd", "--tx_device",
                   help="transmit device",
                   default = None)
    p.add_argument("-d", "--debug",
                   help="debug level",
                   choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                   default='INFO')
    p.add_argument("-a", "--archive_path",
                   help="local path to store archived copies",
                   default="./archive")
    p.add_argument("-m", "--mode",
                   help="Operational mode",
                   choices = ['send', 'receive', 'both'],
                   required = True)
    p.add_argument("-pl", "--pl",
                   help="transmit power level",
                   type = int,
                   choices = range(5),
                   default = 0)

    args = p.parse_args()

    num_xbees = {'send': 1,
                 'receive': 1,
                 'both': 2}

    en_tx = args.mode in ['send', 'both']
    en_rx = args.mode in ['receive', 'both']

    logging.basicConfig(
        level=logging.getLevelName(args.debug),
        handlers=(logging.StreamHandler(sys.stdout),),
        format='%(asctime)s - %(name)s - %(levelname)s %(message)s')

    print("Detecting xbee")
    desc = {}
    for pinfo in list_ports.comports():
        if pinfo.description in desc:
            desc[pinfo.description] += [pinfo.device]
        else:
            desc[pinfo.description] = [pinfo.device]
    print('detected ports:', desc)
    p = None
    for desc, ports in desc.items():
        # may have to add extra descrition checks here...
        if 'FT232' in desc and len(ports) >= num_xbees[args.mode]:
            p = ports

            break
    if (p):
        print('using {} ({})'.format(p, desc))
        if (ok()):
            try:
                if args.mode == 'send':
                    bench(send_dev = args.tx_device if args.tx_device else p[0], **vars(args))
                elif args.mode =='receive':
                    bench(receive_dev = args.rx_device if args.rx_device else p[0], **vars(args))
                else:
                    bench(send_dev = args.tx_device if args.tx_device else p[0],
                          receive_dev = args.rx_device if args.rx_device else p[1], **vars(args))
            except TimeoutError:
                print("Benchmark failed due to timeout communicating with radio, check USB cables.")

            print("Done.")
        else:
            print("Aborted.")
    else:
        print("failed to detect the XBee.")
