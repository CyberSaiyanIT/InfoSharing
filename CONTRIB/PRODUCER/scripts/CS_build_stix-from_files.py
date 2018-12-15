#!/usr/bin/env python
# Informazioni su installazione ed utilizzo https://github.com/CyberSaiyanIT/InfoSharing/tree/master/CONTRIB/PRODUCER/scripts

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

import stix2 

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
    MyTITLE = "Test"

    # La description strutturiamola come segue
    # <IOC PRODUCER> - <Descrizione della minaccia/campagna> - <URL (if any)>
    DESCRIPTION = "Cyber Saiyan - Test - https://infosharing.cybersaiyan.it"

    # La sorgente che ha generato l'IoC con riferimento a Cyber Saiyan Community 
    IDENTITY = "Cyber Saiyan Community"
    #
    ######################################################################

    ########################
    # Commond data
    timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')

    ########################
    # Build STIX 1.2 file
    info_src = InformationSource()
    info_src.identity = Identity(name=IDENTITY)

    NAMESPACE = Namespace("https://infosharing.cybersaiyan.it", "CYBERSAIYAN")
    set_id_namespace(NAMESPACE)

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

    ########################
    # Build STIX 2 file
    pattern_sha256 = []
    pattern_md5 = []
    pattern_sha1 = []
    pattern_domain = []
    pattern_url = []
    pattern_ip = []
    pattern_email = []

    # Marking
    marking_def_white = stix2.MarkingDefinition(
            definition_type="tlp",
            definition={
                "tlp": "WHITE"
            }
    )

    # campagna
    # [TODO] aggiungere tutti i campi dello STIX 1.2 (es. IDENTITY)
    campaign_MAIN = stix2.Campaign(
        created=timestamp,
        modified=timestamp,
        name=MyTITLE,
        description=DESCRIPTION,
        first_seen=timestamp,
        objective="TBD"
    )

    ########################
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
            # STIX 1.2
            filei = File()
            filei.add_hash(Hash(ioc))
        
            obsi = Observable(filei)
            indicatorHASH.add_observable(obsi)
            print "SHA256: " + ioc
            notfound = 0

            # STIX 2
            pattern_sha256.append("[file:hashes.'SHA-256' = '" + ioc +"'] OR ")

        #md5
        p = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)
        m = p.match(ioc)
        if m and notfound:
            # STIX 1.2
            filej = File()
            filej.add_hash(Hash(ioc))
        
            obsj = Observable(filej)
            indicatorHASH.add_observable(obsj)
            print "MD5: " + ioc
            notfound = 0

            # STIX 2
            pattern_md5.append("[file:hashes.'MD5' = '" + ioc +"'] OR ")

        #sha1
        p = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)
        m = p.match(ioc)
        if m and notfound:
            # STIX 1.2
            filek = File()
            filek.add_hash(Hash(ioc))
        
            obsk = Observable(filek)
            indicatorHASH.add_observable(obsk)
            print "SHA1: " + ioc
            notfound = 0

            # STIX 2
            pattern_sha1.append("[file:hashes.'SHA1' = '" + ioc +"'] OR ")

        #domains
        if validators.domain(ioc) and notfound:
            # STIX 1.2
            url = URI()
            url.value = ioc
            url.type_ =  URI.TYPE_DOMAIN
            url.condition = "Equals"

            obsu = Observable(url)
            indiDOMAIN.add_observable(obsu)
            print "DOMAIN: " + ioc
            notfound = 0

            # STIX 2
            pattern_domain.append("[domain-name:value = '" + ioc +"'] OR ")

        #url
        if validators.url(ioc) and notfound:
            # STIX 1.2
            url = URI()
            url.value = ioc
            url.type_ =  URI.TYPE_URL
            url.condition = "Equals"
            
            obsu = Observable(url)
            indiURL.add_observable(obsu)
            print "URL: " + ioc
            notfound = 0

            # STIX 2
            pattern_url.append("[url:value = '" + ioc +"'] OR ")

        #ip
        if validators.ipv4(ioc) and notfound:
            # STIX 1.2
            ip = Address()
            ip.address_value = ioc
        
            obsu = Observable(ip)
            indiIP.add_observable(obsu)
            print "IP: " + ioc
            notfound = 0

            # STIX 2
            pattern_ip.append("[ipv4-addr:value = '" + ioc +"'] OR ")

        #email
        if validators.email(ioc) and notfound:
            # STIX 1.2
            email = EmailAddress()
            email.address_value = ioc

            obsu = Observable(email)
            indiEMAIL.add_observable(obsu)

            print "Email: " + ioc
            notfound = 0

            # STIX 2
            pattern_email.append("[email-message:from_ref.value = '" + ioc +"'] OR ")

    ########################
    # add all indicators to STIX 1.2
    wrapper.add_indicator(indicatorHASH)
    wrapper.add_indicator(indiDOMAIN)
    wrapper.add_indicator(indiURL)
    wrapper.add_indicator(indiIP)
    wrapper.add_indicator(indiEMAIL)

    ########################
    # prepare for STIX 2
    bundle_objects = [campaign_MAIN, marking_def_white]
   
    if len(pattern_sha256)!= 0:
        stix2_sha256 = "".join(pattern_sha256)
        stix2_sha256 = stix2_sha256[:-4]

        indicator_SHA256 = stix2.Indicator(
            name=MyTITLE + " - SHA256",
            created = timestamp,
            modified = timestamp,
            description = DESCRIPTION,
            labels=["malicious-activity"],
            pattern= stix2_sha256,
            object_marking_refs=[marking_def_white]
        )
        relationship_indicator_SHA256 = stix2.Relationship(indicator_SHA256, 'indicates', campaign_MAIN)
        bundle_objects.append(indicator_SHA256)
        bundle_objects.append(relationship_indicator_SHA256)

    if len(pattern_md5)!= 0:
        stix2_md5 = "".join(pattern_md5)
        stix2_md5 = stix2_md5[:-4]

        indicator_MD5 = stix2.Indicator(
            name=MyTITLE + " - MD5",
            created = timestamp,
            modified = timestamp,
            description = DESCRIPTION,
            labels=["malicious-activity"],
            pattern= stix2_md5,
            object_marking_refs=[marking_def_white]
        )
        relationship_indicator_MD5 = stix2.Relationship(indicator_MD5, 'indicates', campaign_MAIN)
        bundle_objects.append(indicator_MD5)
        bundle_objects.append(relationship_indicator_MD5)

    if len(pattern_sha1)!= 0:
        stix2_sha1 = "".join(pattern_sha1)
        stix2_sha1 = stix2_sha1[:-4]

        indicator_SHA1 = stix2.Indicator(
            name=MyTITLE + " - SHA1",
            created = timestamp,
            modified = timestamp,
            description = DESCRIPTION,
            labels=["malicious-activity"],
            pattern= stix2_sha1,
            object_marking_refs=[marking_def_white]
        )
        relationship_indicator_SHA1 = stix2.Relationship(indicator_SHA1, 'indicates', campaign_MAIN)
        bundle_objects.append(indicator_SHA1)
        bundle_objects.append(relationship_indicator_SHA1)

    if len(pattern_domain)!= 0:
        stix2_domain = "".join(pattern_domain)
        stix2_domain = stix2_domain[:-4]
        
        indicator_DOMAINS = stix2.Indicator(
            name=MyTITLE + " - DOMAINS",
            created = timestamp,
            modified=timestamp,
            description=DESCRIPTION,
            labels=["malicious-activity"],
            pattern= stix2_domain,
            object_marking_refs=[marking_def_white]
        )
        relationship_indicator_DOMAINS = stix2.Relationship(indicator_DOMAINS, 'indicates', campaign_MAIN)
        bundle_objects.append(indicator_DOMAINS)
        bundle_objects.append(relationship_indicator_DOMAINS)

    if len(pattern_url)!= 0:
        stix2_url = "".join(pattern_url)
        stix2_url = stix2_url[:-4]

        indicator_URLS = stix2.Indicator(
            name=MyTITLE + " - URL",
            created = timestamp,
            modified=timestamp,
            description=DESCRIPTION,
            labels=["malicious-activity"],
            pattern= stix2_url,
            object_marking_refs=[marking_def_white]
        )
        relationship_indicator_URLS = stix2.Relationship(indicator_URLS, 'indicates', campaign_MAIN)
        bundle_objects.append(indicator_URLS)
        bundle_objects.append(relationship_indicator_URLS)

    if len(pattern_ip)!= 0:
        stix2_ip = "".join(pattern_ip)
        stix2_ip = stix2_ip[:-4]
    
        indicator_IPS = stix2.Indicator(
            name=MyTITLE + " - IPS",
            created = timestamp,
            modified=timestamp,
            description=DESCRIPTION,
            labels=["malicious-activity"],
            pattern= stix2_ip,
            object_marking_refs=[marking_def_white]
        )
        relationship_indicator_IPS = stix2.Relationship(indicator_IPS, 'indicates', campaign_MAIN)
        bundle_objects.append(indicator_IPS)
        bundle_objects.append(relationship_indicator_IPS)
    
    if len(pattern_email)!=0:
        stix2_email = "".join(pattern_email)
        stix2_email = stix2_email[:-4]

        indicator_EMAILS = stix2.Indicator(
            name=MyTITLE + " - EMAILS",
            created = timestamp,
            modified=timestamp,
            description=DESCRIPTION,
            labels=["malicious-activity"],
            pattern= stix2_email,
            object_marking_refs=[marking_def_white]
        )
        relationship_indicator_EMAILS = stix2.Relationship(indicator_EMAILS, 'indicates', campaign_MAIN)
        bundle_objects.append(indicator_EMAILS)
        bundle_objects.append(relationship_indicator_EMAILS)

    # creo il bunble STIX 2
    bundle = stix2.Bundle(objects=bundle_objects)
   
    ########################
    # save to STIX 1.2 file
    print 
    print "Writing STIX package: package.stix"
    f = open ("package.stix", "w")
    f.write (wrapper.to_xml())
    f.close ()
    

    ########################
    # save to STIX 2 file
    print "Writing STIX 2 package: package.stix2"
    g = open ("package.stix2", "w")
    sys.stdout = g
    print bundle

if __name__ == '__main__':
    main()
    print
