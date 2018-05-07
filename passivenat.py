# -*- coding: utf-8 -*-
"""
Created on Sun May  6 19:10:28 2018

@author: aslan.varoqua@duasamericasgroup.com
"""

import os
import subprocess, threading
from subprocess import PIPE,Popen
from flock import flock
import pandas as pd
import pymongo
import uuid
from subprocess import PIPE
import time
from optparse import OptionParser
from pymongo import MongoClient
client = MongoClient()
db = client['ip']
conn = db['pandas']
import ipaddress

# unique id of nat count run
log_id = str(uuid.uuid1())
# parsing command line options and setting defaults 
parser = OptionParser()
parser.add_option("-i", "--interface", dest="interface", default="eno2",
                  help="device to attach for listening")
parser.add_option("-p", "--pcap", dest="pcap", default=None,
                  help="use pcap file")
parser.add_option("-f", "--filter", dest="filter", default=" ",
                  help="use pcap file")
parser.add_option("-d", "--dir", dest="logdir", default="/var/log/p0f/",
                  help="use pcap file")
parser.add_option("-u", "--uniqueid", dest="uniqueid", default=log_id,
                  help="custom data identifier")
parser.add_option("-c", "--cleanup", dest="cleanup", default=True,
                  help="custom data identifier")
parser.add_option("-m", "--minutes", dest="minutes", default=10,
                  help="minutes")
(options, args) = parser.parse_args()
# unique id of nat count run

# pipeline for aggregating the dataframe
pipeline = [
        {"$group": {"_id": { "cip" : "$cip" }, "raw_ips": {"$addToSet": "$raw_ip"}}},
        {"$unwind" : "$raw_ips" },
        {"$group":{"_id":"$_id" , "count" :{ "$sum" : 1}}},
        {"$out" : str(options.uniqueid) + "-devices" }
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
        db[str(options.uniqueid) + 'raw'].insert_many(df2.to_dict('records'))

#location of the p0f logger
logfile = options.logdir + str(options.uniqueid)

#command class to keep processes organized and control threads
class Command(object):
    def __init__(self, cmd):
        self.cmd = cmd
        self.process = None

    def run(self, timeout):
        def target():
            print('Thread started')
	    print(str(self.cmd))
	    if "./p0f/p0f" in str(self.cmd):	
	 	self.process = Popen(self.cmd,shell=True)
		self.process.communicate()
		time.sleep(options.minutes)
		self.process.kill()
	    else:
		self.process = Popen(self.cmd,shell=True)
            	self.process.communicate()
	    #self.process = subprocess.Popen(self.cmd, )
            
	    print('Thread finished')

        thread = threading.Thread(target=target)
        thread.start()

        thread.join(timeout)
        if thread.is_alive():
            print('Terminating process')
            self.process.terminate()
            thread.join()
        #print(self.process.returncode)
        
# function to clean old p0f logs and processes
def clean_old():
	#if options.cleanup:
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
	command = Command("./p0f/p0f " + "-i " + options.interface + " -o " + logfile)
	command.run(timeout=options.minutes)
# apply tcp filter
def grep_log():
	command = Command("grep -P '^(?=.*raw_sig)(?=.*" +
                           options.filter + " )' > " + logfile + "-filtered.csv")
	command.run(timeout=options.minutes)		

#split large logs
def split():
   command = Command("split -l 10000 " + logfile + 
                                 "-clean.csv " + " segment")
   command.run(timeout=5)
   command = Command("rm " + logfile)
   command.run(timeout=options.minutes)
   command = Command("rm " + logfile + "-clean.csv")
   command.run(timeout=options.minutes)




def process_df():
    print(list(db[options.uniqueid].aggregate(pipeline)))
    

def main():
    ## ========
    ## a message that there is a lock in place and exit.
    lock = flock('tmp.lock', True).acquire()
    
    if lock:
        clean_old()
        p0f()
        grep_log()
        split()
        process_df()
        clean_old()
        
    else:
        print('someone else is working here!')




if __name__ == "__main__":
       main()
