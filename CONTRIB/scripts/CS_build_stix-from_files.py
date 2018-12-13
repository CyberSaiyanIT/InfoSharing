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
# - Adattare le variabili di riga 88, riga 92 e riga 95
#
# - prima di procedere resettare il contenuto dei file CS-*.txt
#   ~$ for file in CS-*.txt; do > $file; done
#
# - inserire gli IoC supportati (sha256, sha1, md5, domain, ipv4, url) nel file CS-ioc.txt
#   lo script parsa il file linea per linea e usa delle espressioni regolari per validare gli IoC
#   commenti o IoC malformati vengono ignorati
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
    MyTITLE = "GandCrab"

    # La description strutturiamola come segue
    # <IOC PRODUCER> - <Descrizione della minaccia/campagna> - <URL (if any)>
    DESCRIPTION = "CERT-PA - Nuova campagna di Cyber-Estorsione basata su ransomware GandCrab - https://www.cert-pa.it/notizie/nuova-campagna-di-cyber-estorsione-basata-su-ransomware-gandcrab/"

    # La sorgente che ha generato l'IoC con riferimento a Cyber Saiyan Community 
    IDENTITY = "CERT-PA via Cyber Saiyan Community"
    #
    ######################################################################

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
    
    # DOMAIN indicators
    indiDOMAIN = Indicator()
    indiDOMAIN.title = MyTITLE + " - DOMAIN"
    indiDOMAIN.add_indicator_type("Domain Watchlist")

    # URL indicators
    indiURL = Indicator()
    indiURL.title = MyTITLE + " - URL"
    indiURL.add_indicator_type("URL Watchlist")

    # IP indicators
    indiIP = Indicator()
    indiIP.title = MyTITLE + " - IP"
    indiIP.add_indicator_type("IP Watchlist")

    # EMAIL indicators
    indiEMAIL = Indicator()
    indiEMAIL.title = MyTITLE + " - EMAIL"
    indiEMAIL.add_indicator_type("Malicious E-mail")

    # Read IoC file
    file_ioc = "CS-ioc.txt"
    ioc = loaddata(file_ioc)

    print "Reading IoC file..."
    for idx, ioc in enumerate(ioc):
        notfound = 1
        
        # sha256
        p = re.compile(r"^[0-9a-f]{64}$", re.IGNORECASE)
        m = p.match(ioc)
        if m and notfound:
            filei = File()
            filei.add_hash(Hash(ioc))
        
            obsi = Observable(filei)
            indicatorHASH.add_observable(obsi)
            print "SHA256: " + ioc
            notfound = 0

        #md5
        p = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)
        m = p.match(ioc)
        if m and notfound:
            filej = File()
            filej.add_hash(Hash(ioc))
        
            obsj = Observable(filej)
            indicatorHASH.add_observable(obsj)
            print "MD5: " + ioc
            notfound = 0

        #sha1
        p = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
        m = p.match(ioc)
        if m and notfound:
            filek = File()
            filek.add_hash(Hash(ioc))
        
            obsk = Observable(filek)
            indicatorHASH.add_observable(obsk)
            print "SHA1: " + ioc
            notfound = 0

        #domains
        if validators.domain(ioc) and notfound:
            url = URI()
            url.value = ioc
            url.type_ =  URI.TYPE_DOMAIN
            url.condition = "Equals"

            obsu = Observable(url)
            indiDOMAIN.add_observable(obsu)
            print "DOMAIN: " + ioc
            notfound = 0

        #url
        if validators.url(ioc) and notfound:
            url = URI()
            url.value = ioc
            url.type_ =  URI.TYPE_URL
            url.condition = "Equals"
            
            obsu = Observable(url)
            indiURL.add_observable(obsu)
            print "URL: " + ioc
            notfound = 0

        #ip
        if validators.ipv4(ioc) and notfound:
            ip = Address()
            ip.address_value = ioc
        
            obsu = Observable(ip)
            indiIP.add_observable(obsu)
            print "IP: " + ioc
            notfound = 0

    # add all indicators to STIX
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
