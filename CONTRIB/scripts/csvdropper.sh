#!/bin/bash
dir=/etc/graylog/lookupcsv
filename=graylog_ti.csv
cd /tmp/
if [ ! -d /tmp/minemeld_appo/ ]; then
 mkdir minemeld_appo
fi
cd minemeld_appo
rm -f $filename
# 
/usr/bin/wget -O $filename 'https://infosharing.cybersaiyan.it/feeds/CS-COMMUNITY-HTTP?v=csv&f=type&f=indicator&tr=1' --no-check-certificate --timeout=2 --tries=5
if [ $? -eq 0 ];
then
 mv $filename $dir
else
 echo "ERROR"
 exit 1
fi
exit 0
