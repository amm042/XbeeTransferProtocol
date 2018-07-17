


import logging
import sys
import os.path
import logging.handlers
import hexdump
import time
import datetime
import dateutil.tz
import argparse
import shutil
from xTPSend import XTPClient
from xbee.ieee import XBee as XBeeS1
from xb900hp import XBee900HP
            
                
if __name__ == "__main__":
    # run the Client
    
    p = argparse.ArgumentParser()
    
    p.add_argument("portstr", help="pylink style port string eg: /dev/ttyUSB0:38400:8N1")
    p.add_argument("srcpath", help="source path to archive")
    p.add_argument("archive_path", help="local path to store archived copies")
    
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
 
        fmt = '%Y-%m-%dT%H:%M:%S %Z'
        session_str = datetime.datetime.now(dateutil.tz.tzlocal()).strftime(fmt)

        logging.info("Archive {} to {}".format(args.srcpath,
                                               os.path.join(args.archive_path, session_str)))
        
        first = True
        #session_str = 'TEST'
        
        
        for filename in os.listdir(args.srcpath):
            srcpf = os.path.join(os.path.abspath(args.srcpath), filename)
            if not os.path.isfile(srcpf):
                logging.info("Skip \"{}\", it's not a file.".format(srcpf))
                continue
            
            if os.path.getsize(srcpf) == 0:
                logging.info("{} is a zero byte file.".format(filename))
                continue

            if first:
                os.makedirs(os.path.join(os.path.abspath(args.archive_path), session_str), 
                    exist_ok= True)
                first = False
                                        
            arcpf = os.path.join(os.path.abspath(args.archive_path), session_str, filename)
            remote_filename = os.path.join(session_str, filename)
                        
            logging.info("Send {}".format(srcpf))
            start = datetime.datetime.now()
            if xtp.send_file(srcpf, remote_filename):
                result = xtp.verify(srcpf, remote_filename)
                t = (datetime.datetime.now() - start).total_seconds()
                sz = os.path.getsize(srcpf)
                logging.info("Sent {} verified={}, {:.2f} kbps.".format(srcpf, result,
                                                              (8*sz/1024)/t))
                
                if result:
                    logging.info("Archive {} --> {}.".format(srcpf, arcpf))
                    shutil.move(srcpf, arcpf)
                else:
                    logging.error("NOT Arching -- verify failed for {}".format(remote_filename))
        if first:
            logging.info ("No files to archive in {}".format(args.srcpath))                                                                
        else:
            logging.info ("All files archived from {} to {}".format(args.srcpath, 
                                                                os.path.join(args.archive_path, session_str)))
    finally:
        if xtp != None:
            xtp.xbee.close()
            
            