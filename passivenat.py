# -*- coding: utf-8 -*-
"""
Created on Sun May  6 19:10:28 2018

@author: aslan.varoqua@duasamericasgroup.com
"""

import os
import subprocess, threading
from flock import flock
import pandas as pd
import pymongo
import uuid

from optparse import OptionParser

# unique id of nat count run
log_id = uuid.uuid1()

# pipeline for aggregating the dataframe
pipeline = [
        {"$group": {"_id": { "cip" : "$cip" }, "raw_ips": {"$addToSet": "$raw_ip"}}},
        {"$unwind" : "$raw_ips" },
        {"$group":{"_id":"$_id" , "count" :{ "$sum" : 1}}},
        {"$sort": SON([("count", -1), ("_id", -1)])},
        {"$out" : uniqueid + "-devices" }
]

def p0f_parse(inFile):
        df2 = pd.read_csv( inFile,sep='|',header=0, engine='python')
        df2.columns = [
                'time',
                'client_ip',
                'server_ip',
                'd',
                'connection',
                'mtu',
                'g',
                'raw_ip'
        ]
        #df2.sort_values(by=['client_ip'])
        #grouped = df2.groupby(['client_ip','raw_ip'])
        df2['client_ip'] = df2['client_ip'].map(lambda x: str(x)[4:])
        df2['server_ip'] = df2['server_ip'].map(lambda x: str(x)[4:])
        #df2['mtu'] = df2['mtu'].map(lambda x:  x.lstrip('raw_mtu=langEnglishnonefreqdistHz').rstrip('=Hz'))
        df2['time'] = df2['time'].map(
                lambda x:  x.lstrip('')
                .rstrip(
                        'mod=mtu,cli=mod=syn+ackmod=uptimemod=httpreqmod= ' +
                        'httpmod=host chang'
                        )
                )
        #i#3df2_checkpub = df2['client_ip'].apply(lambda x: ipaddress.ip_address(x).is_global)
        #df2_checkpriv = df2['client_ip'].apply(lambda x: ipaddress.ip_address(x).is_private)
        df2['cip'] = df2['client_ip'].apply(lambda x: x.split('/')[0])
        df2['sip'] = df2['server_ip'].apply(lambda x: x.split('/')[0])
        db[uniqueid + 'raw'].insert_many(df2.to_dict('records'))

# parsing command line options and setting defaults 
parser = OptionParser()
parser.add_option("-i", "--interface", dest="interface", default="eno2",
                  help="device to attach for listening")
parser.add_option("-p", "--pcap", dest="pcap", default=None,
                  help="use pcap file")
parser.add_option("-f", "--filter", dest="filter", default=" ",
                  help="use pcap file")
parser.add_option("-d", "--dir", dest="logdir", default=log_dir,
                  help="use pcap file")
parser.add_option("-u", "--uniqueid", dest="uniqueid", default=log_id,
                  help="custom data identifier")
parser.add_option("-c", "--cleanup", dest="cleanup", default=True,
                  help="custom data identifier")
parser.add_option("-m", "--minutes", dest="uniqueid", default=10,
                  help="minutes")


(options, args) = parser.parse_args()

#location of the p0f logger
logfile = options.logdir + options.uniqueid

#command class to keep processes organized and control threads
class Command(object):
    def __init__(self, cmd):
        self.cmd = cmd
        self.process = None

    def run(self, timeout):
        def target():
            print('Thread started')
            self.process = subprocess.Popen(self.cmd, shell=True)
            self.process.communicate()
            print('Thread finished')

        thread = threading.Thread(target=target)
        thread.start()

        thread.join(timeout)
        if thread.is_alive():
            print('Terminating process')
            self.process.terminate()
            thread.join()
        print(self.process.returncode)
        
# function to clean old p0f logs and processes
def clean_old():
	if options.cleanup:
        command = Command("rm -rf /var/log/p0f/*")
        command.run(timeout=1)
        command = Command("pkill -n p0f")
        command.run(timeout=1)
        command = Command("pkill -f p0f")
        command.run(timeout=1)
        command = Command("pkill -f passive_nat")
        command.run(timeout=1)
        command = Command("pkill -n passive_nat")
        command.run(timeout=1)

#start p0f
def p0f():
	command = Command("./p0f " + "-i " + options.interface + " -o " + logfile)
	command.run(timeout=options.minutes)

# apply tcp filter
def filter():
	command = Command("grep -P '^(?=.*raw_sig)(?=.*" +
                           filter + " )' > " + logfile + "-filtered.csv")
	command.run(timeout=options.minutes)		

#split large logs
def split():
   command = Command("split -l 10000 " + logfile + 
                                 "-clean.csv " + " segment")
   command.run(timeout=5)
   command = Command("rm " + logfile)
   command.run(timeout=options.minutes)
   command = Command("rm " + logfile + "-clean.csv)
   command.run(timeout=options.minutes)




def process_df():
    pprint.pprint(list(db[uniqueid].aggregate(pipeline)))
    

def main():
    ## ========
    ## a message that there is a lock in place and exit.
    lock = flock('tmp.lock', True).acquire()
    
    if lock:
        clean_old()
        p0f()
        filter()
        split()
        process_df()
        clean_old()
        
    else:
        print('someone else is working here!')




if __name__ == "__main__":
       main()
