#!/usr/bin/env python

################
# Requirements
#
# - cabby 
#   ~$ pip install cabby
#
# - python-cybox==2.1.0.12 [TODO verificare versione corrente]
#   ~$ git clone https://github.com/CybOXProject/python-cybox.git
#   ~$ cd python-cybox/
#   ~$ git checkout v2.1.0.12
#   ~$ sudo python setup.py install
#
# - python-stix==1.1.1.4 [TODO verificare versione corrente]
#   ~$ git clone https://github.com/STIXProject/python-stix.git
#   ~$ cd python-stix
#   ~$ git checkout v1.1.1.4
#   ~$ sudo python setup.py install 
#
# - stix
#   ~$ pip install stix
#
# - validators
#   ~$ pip install validators

##################################
# PUSH degli IoC sulla rete Cyber Saiyan
#
# - Adattare le variabili di riga 93, riga 97 e riga 100
#
# - prima di procedere resettare il contenuto dei file CS-*.txt
#   ~$ for file in CS-*.txt; do > $file; done
#
# - inserire i vari IoC nei file corrispondenti
#   - domain --> CS-domain.txt
#   - ipv4 --> CS-ipv4.txt
#   - sha256 --> CS-sha256.txt
#   - sha1 --> CS-sha1.txt
#   - md5 --> CS-md5.txt
#   - url --> CS-url.txt
#   - email --> CS-email.txt
#
# - Generazione del file STIX da pushare successivamente sulla rete (file: package.stix)
#   ~$ python -W ignore CS_build_stix.py
#
# - PUSH via Cabby del file package.stix sulla collection dedicata "community" (la password per il push deve essere richiesta sul gruppo Telegram dedicato)
#   ~$ taxii-push --discovery https://infosharing.cybersaiyan.it:9000/services/discovery --dest community --username community --password <TO-BE-SENT> --content-file package.stix
#
# - Verifica via Cabby degli IoC (tempo di aggiornamento massimo 10 minuti)
#   ~$ taxii-poll --host infosharing.cybersaiyan.it --https --collection CS-COMMUNITY-TAXII --discovery /taxii-discovery-service

import sys
import os.path
import time
import datetime
import validators
import re

from stix.core import STIXPackage, STIXHeader
from stix.data_marking import Marking, MarkingSpecification
from stix.extensions.marking.tlp import TLPMarkingStructure
from stix.common import InformationSource, Identity
from stix.indicator import Indicator

from mixbox.idgen import set_id_namespace
from mixbox.namespaces import Namespace

from cybox.core import Observable
from cybox.common import Hash
from cybox.objects.file_object import File
from cybox.objects.uri_object import URI
from cybox.objects.address_object import Address
from cybox.objects.email_message_object import EmailAddress

def loaddata(file_in):
    if os.path.exists(file_in) and os.path.getsize(file_in) > 0:
        with open(file_in) as data_file:
            try:
                data = data_file.readlines()
                return [x.strip() for x in data] 
            except ValueError, error:
                return []
    else:
        return []

def main():

    ######################################################################
    # MODIFICARE LE VARIABILI SEGUENTI

    # Il title e' ID univoco della minaccia (es. Cobalt / Danabot / APT28)
    MyTITLE = "Gootkit"

    # La description strutturiamola come segue
    # <IOC PRODUCER> - <Descrizione della minaccia/campagna> - <URL (if any)>
    DESCRIPTION = "D3Lab - Malspam Gootkit con dropper da 450+ MB - https://www.d3lab.net/malspam-gootkit-con-dropper-da-450-mb/"

    # La sorgente che ha generato l'IoC con riferimento a Cyber Saiyan Community 
    IDENTITY = "D3Lab via Cyber Saiyan Community"
    #
    ######################################################################

    # read IoC files
    file_sha256 = "CS-sha256.txt"
    sha256 = loaddata(file_sha256)

    file_md5 = "CS-md5.txt"
    md5 = loaddata(file_md5)

    file_sha1 = "CS-sha1.txt"
    sha1 = loaddata(file_sha1)

    file_domains = "CS-domain.txt"
    domains = loaddata(file_domains)

    file_urls = "CS-url.txt"
    urls = loaddata(file_urls)

    file_ips = "CS-ipv4.txt"
    ips = loaddata(file_ips)

    file_emails = "CS-email.txt"
    emails = loaddata(file_emails)

    # Build STIX file
    info_src = InformationSource()
    info_src.identity = Identity(name=IDENTITY)

    NAMESPACE = Namespace("https://infosharing.cybersaiyan.it", "CYBERSAIYAN")
    set_id_namespace(NAMESPACE)

    timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
    SHORT = timestamp

    wrapper = STIXPackage()
    
    marking_specification = MarkingSpecification()
    marking_specification.controlled_structure = "//node() | //@*"
    tlp = TLPMarkingStructure()
    tlp.color = "WHITE"
    marking_specification.marking_structures.append(tlp)
    
    handling = Marking()
    handling.add_marking(marking_specification)
    
    wrapper.stix_header = STIXHeader(information_source=info_src, title=MyTITLE.encode(encoding='UTF-8', errors='replace'), description=DESCRIPTION.encode(encoding='UTF-8', errors='replace'), short_description=SHORT.encode(encoding='UTF-8', errors='replace'))
    wrapper.stix_header.handling = handling
    
    # HASH indicators
    indicatorHASH = Indicator()
    indicatorHASH.title = MyTITLE + " - HASH"
    indicatorHASH.add_indicator_type("File Hash Watchlist")
    
    print "Reading IoC sha256 file..."
    p = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
    for idx, sha256 in enumerate(sha256):
        m = p.match(sha256)
        if m:
    	    filei = File()
            filei.add_hash(Hash(sha256))
    	
            obsi = Observable(filei)
            indicatorHASH.add_observable(obsi)
        else:
            print " Malformed sha256: " + sha256
    print
    
    print "Reading IoC md5 file..."
    p = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)
    for idx, md5 in enumerate(md5):
        m = p.match(md5)
        if m:
    	    filej = File()
            filej.add_hash(Hash(md5))
    	
            obsj = Observable(filej)
            indicatorHASH.add_observable(obsj)
        else:
            print " Malformed md5: " + md5
    print

    print "Reading IoC sha1 file..."
    p = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
    for idx, sha1 in enumerate(sha1):
        m = p.match(sha1)
        if m:
    	    filek = File()
            filek.add_hash(Hash(sha1))
    	
            obsk = Observable(filek)
            indicatorHASH.add_observable(obsk)
        else:
            print " Malformed sha1: " + sha1
    print
    
    # DOMAIN indicators
    indiDOMAIN = Indicator()
    indiDOMAIN.title = MyTITLE + " - DOMAIN"
    indiDOMAIN.add_indicator_type("Domain Watchlist")

    print "Reading IoC domains file..."
    for idu, domains in enumerate(domains):
        if validators.domain(domains):
            url = URI()
            url.value = domains
	    url.type_ =  URI.TYPE_DOMAIN
	    url.condition = "Equals"

            obsu = Observable(url)
            indiDOMAIN.add_observable(obsu)
        else:
            print " Malformed domain: " + domains
    print
        

    # URL indicators
    indiURL = Indicator()
    indiURL.title = MyTITLE + " - URL"
    indiURL.add_indicator_type("URL Watchlist")

    print "Reading IoC url file..."
    for idu, urls in enumerate(urls):
        if validators.url(urls):
            url = URI()
            url.value = urls
	    url.type_ =  URI.TYPE_URL
	    url.condition = "Equals"
            
            obsu = Observable(url)
            indiURL.add_observable(obsu)
        else:
            print " Malformed url: " + urls
    print

    # IP indicators
    indiIP = Indicator()
    indiIP.title = MyTITLE + " - IP"
    indiIP.add_indicator_type("IP Watchlist")

    print "Reading IoC IP file..."
    for idu, ips in enumerate(ips):
        if validators.ipv4(ips):
            ip = Address()
	    ip.address_value = ips
        
            obsu = Observable(ip)
            indiIP.add_observable(obsu)
        else:
            print " Malformed IP: " + ips
    print

    # EMAIL indicators
    indiEMAIL = Indicator()
    indiEMAIL.title = MyTITLE + " - EMAIL"
    indiEMAIL.add_indicator_type("Malicious E-mail")

    print "Reading IoC email file..."
    for idu, emails in enumerate(emails):
        if validators.email(emails):
            email = EmailAddress()
	    email.address_value = emails
        
            obsu = Observable(email)
            indiEMAIL.add_observable(obsu)
        else:
            print " Malformed email: " + emails
    print

    # add all indicators
    wrapper.add_indicator(indicatorHASH)
    wrapper.add_indicator(indiDOMAIN)
    wrapper.add_indicator(indiURL)
    wrapper.add_indicator(indiIP)
    wrapper.add_indicator(indiEMAIL)
   
    # print STIX file to stdout
    print "Writing STIX package: package.stix"
    f = open ("package.stix", "w")
    f.write (wrapper.to_xml())
    f.close ()
    print 
    
if __name__ == '__main__':
    main()
