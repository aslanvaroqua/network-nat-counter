# passivenat
passivenat is a tool, written in python to attach to a network interface for device fingerprinting. This can be useful in learning about a network topology passively without generating any packets. Uses the good old p0f program and has been tested and scales onto a good size network... However, the big-data-net-analytics can take care of fingerprinting on large networks although its not in real time. 

*must be super user for live devices 
```
sudo -i
```

install deps
```
sudo apt-get install mongodb
sudo apt-get install pcaplib-dev
```
Create a folder to use as a mount point for your RAM disk.

```
mkdir /mnt/tmpfs
```

Then use the mount command to create a RAM disk.
```
mount -t [TYPE] -o size=[SIZE] [FSTYPE] [MOUNTPOINT]
```

Substitute the following attirbutes for your own values:

[TYPE] is the type of RAM disk to use; either tmpfs or ramfs.
[SIZE] is the size to use for the file system. Remember that ramfs does not have a physical limit and is specified as a starting size. We have lots of traffic so we are setting to 16GB 
[FSTYPE] is the type of RAM disk to use; either tmpfs, ramfs, ext4, etc.

start mongod
```
mongod --smallfiles --nojournal --dbpath /mnt/tmpfs
```

make python virtual environment * important
from root folder:
```
pip install virtualenv
virtualenv .
source ./bin/activate
```

install reqs
```
pip install -r requirements.txt
```

set options and run 
```
# parsing command line options and setting defaults 
parser = OptionParser()
parser.add_option("-i", "--interface", dest="interface", default="eno2",
                  help="device to attach for listening")
parser.add_option("-p", "--pcap", dest="pcap", default=None,
                  help="use pcap file")
parser.add_option("-f", "--filter", dest="filter", default=" ",
                  help="use pcap file")
parser.add_option("-d", "--dir", dest="logdir", default=default=log_dir",
                  help="use pcap file")
parser.add_option("-u", "--uniqueid", dest="uniqueid", default=log_id,
                  help="custom data identifier")
parser.add_option("-c", "--cleanup", dest="cleanup", default=True,
                  help="custom data identifier")
parser.add_option("-m", "--minutes", dest="uniqueid", default=10,
                  help="minutes")
```

finally:
```
python passivenat.py -i etho -f {ipaddressToFilter} --u {someuniqueidforthedata} -m {minutestocollectdata}
```
