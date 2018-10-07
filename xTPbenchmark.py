from xTPListen import XTPServer
from xTPSend import XTPClient
from xbee import XBee as XBeeS1

from serial.tools import list_ports

import threading
import logging
import sys
from datetime import datetime

def ok():
    user = '!'
    while not user in 'YyNn' and user != '':
        user = input("Ok? [Y/n]: ")

    return user in 'yY' or user == ''


def bench(txdev, rxdev, baud=38400, opts="8N1"):
    "This is setup for two XBee S1's"

    rx = XTPServer(
        "{}:{}:{}".format(rxdev, baud, opts),
        "./tmp",
        XBeeS1)

    rx_thread = threading.Thread(
        target=rx.run_forever,
        name="Bench Rx Thread")
    rx_thread.start()

    tx = XTPClient(
        "{}:{}:{}".format(txdev, baud, opts),
        XBeeS1)

    #$ dd if=/dev/urandom of=test-1M.dat bs=1M count=1

    result = {}
    for tries in range(16):
        for cs in [1,2,4,8,16,32,64]:
            start = datetime.now()
            tx.xbee.rssi_history = []
            rx.xbee.rssi_history = []
            r = tx.send_file('test-8M.dat', chunk_size = 1024*cs)
            end = datetime.now()

            if (r):
                if cs in result:
                    result[cs] += [ (end-start,
                                     tx.xbee.avg_rssi(),
                                     rx.xbee.avg_rssi()) ]
                else:
                    result[cs] = [ (end-start,
                                    tx.xbee.avg_rssi(),
                                    rx.xbee.avg_rssi()) ]
            else:
                print("{}K = {}".format(cs, "Failed!"))

            # print partial results if we crash it's ok
            for cs, r in result.items():
                print("-"*80)
                print("{}K".format(cs))
                print(", ".join(["{}".format(z[0]) for z in r]))
                print(", ".join(["{}".format(z[1]) for z in r]))
                print(", ".join(["{}".format(z[2]) for z in r]))

    rx.stop()
    rx_thread.join()
    rx.xbee.close()
    tx.xbee.close()
    print("-"*80)

if __name__=="__main__":

    logging.basicConfig(
        level=logging.INFO,
        handlers=(logging.StreamHandler(sys.stdout),),
        format='%(asctime)s - %(name)s - %(levelname)s %(message)s')

    desc = {}
    for pinfo in list_ports.comports():
        if pinfo.description in desc:
            desc[pinfo.description] += [pinfo.device]
        else:
            desc[pinfo.description] = [pinfo.device]

    p = None
    for desc, ports in desc.items():
        if len(ports) == 2:
            p = ports
            break
    if (p):
        print('using {} ({})'.format(p, desc))
        if (ok()):

            bench(p[0], p[1])

            print("Done.")
        else:
            print("Aborted.")
