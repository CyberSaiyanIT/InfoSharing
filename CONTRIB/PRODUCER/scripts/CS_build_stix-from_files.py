#!/usr/bin/python3
# Informazioni su installazione ed utilizzo https://github.com/CyberSaiyanIT/InfoSharing/tree/master/CONTRIB/PRODUCER/scripts

import sys
import getopt
import os

from datetime import datetime
import validators
import re

import warnings

if not sys.warnoptions:
    warnings.simplefilter("ignore")

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
from cybox.objects.address_object import EmailAddress
from cybox.objects.email_message_object import EmailAddress

from cybox.objects.email_message_object import EmailMessage

import stix2


def verifyhash(hashvalue, hashtype):
    if hashtype == "sha256":
        verify = re.findall(r"^[0-9a-f]{64}$", hashvalue, re.IGNORECASE)
        if verify:
            return True

    if hashtype == "sha1":
        verify = re.findall(r"^[0-9a-f]{40}$", hashvalue, re.IGNORECASE)
        if verify:
            return True

    if hashtype == "md5":
        verify = re.findall(r"^[0-9a-f]{32}$", hashvalue, re.IGNORECASE)
        if verify:
            return True

    return False


def loaddata(file_in):
    if os.path.exists(file_in) and os.path.getsize(file_in) > 0:

        typeofdata = "null"

        global listSHA256
        listSHA256 = []

        global listSHA1
        listSHA1 = []

        global listMD5
        listMD5 = []

        global listDOMAIN
        listDOMAIN = []

        global listURL
        listURL = []

        global listIP
        listIP = []

        global listEMAIL
        listEMAIL = []

        global listSUBJECT
        listSUBJECT = []

        f = open(file_in, "r", errors="ignore")

        # Remove empty line
        lines = filter(None, (line.rstrip() for line in f))

        for line in lines:
            if line:
                if line.startswith("#"):
                    continue

                if line == "::SHA256::":
                    typeofdata = "SHA256"
                    continue

                if line == "::SHA1::":
                    typeofdata = "SHA1"
                    continue

                if line == "::MD5::":
                    typeofdata = "MD5"
                    continue

                if line == "::DOMAIN::":
                    typeofdata = "DOMAIN"
                    continue

                if line == "::URL::":
                    typeofdata = "URL"
                    continue

                if line == "::IP::":
                    typeofdata = "IP"
                    continue

                if line == "::EMAIL::":
                    typeofdata = "EMAIL"
                    continue

                if line == "::SUBJECT::":
                    typeofdata = "SUBJECT"
                    continue

                if typeofdata == "SHA256":
                    if verifyhash(line, "sha256"):
                        listSHA256.append(line)

                if typeofdata == "SHA1":
                    if verifyhash(line, "sha1"):
                        listSHA1.append(line)

                if typeofdata == "MD5":
                    if verifyhash(line, "md5"):
                        listMD5.append(line)

                if typeofdata == "DOMAIN":
                    if validators.domain(line):
                        listDOMAIN.append(line)

                if typeofdata == "URL":
                    if validators.url(line):
                        listURL.append(line)

                if typeofdata == "IP":
                    if validators.ipv4(line):
                        listIP.append(line)

                if typeofdata == "EMAIL":
                    if validators.email(line):
                        listEMAIL.append(line)

                if typeofdata == "SUBJECT":
                    listSUBJECT.append(line)

        f.close()


def main(argv):
    ######################################################################
    # Se non impostati da command line vengono utilizzati i seguenti valori per TITLE, DESCRIPTION, IDENTITY
    # Il title e' ID univoco della minaccia (es. Cobalt / Danabot / APT28)
    TITLE = "Test"

    # La description strutturiamola come segue
    # <IOC PRODUCER> - <Descrizione della minaccia/campagna> - <URL (if any)>
    DESCRIPTION = "Cyber Saiyan - Test - https://infosharing.cybersaiyan.it"

    # La sorgente che ha generato l'IoC con riferimento a Cyber Saiyan Community 
    IDENTITY = "Cyber Saiyan Community"

    # File degli IoC
    IOCFILE = "CS-ioc.txt"

    # Prefisso STIX output files STIX 1.2 e STIX 2
    OUTFILEPREFIX = "package"

    # Short Description - UNUSED
    SHORT = "unused"
    ######################################################################

    VERBOSE = 0

    # Parse ARGV[]
    try:
        opts, args = getopt.getopt(argv, "ht:d:i:f:o:v")
    except getopt.GetoptError:
        print(
            "CS_build_stix-from_files.py [-t TITLE] [-d DEMAILESCRIPTION] [-i IDENTITY] [-f IOC_FILE] [-o STIX_FILES_PREFIX]")
        sys.exit(2)

    for opt, arg in opts:
        if opt == "-h":
            print(
                "CS_build_stix-from_files.py [-t TITLE] [-d DESCRIPTION] [-i IDENTITY] [-f IOC_FILE] [-o STIX_FILES_PREFIX]")
            sys.exit()
        elif opt == "-t":
            TITLE = arg
        elif opt == "-d":
            DESCRIPTION = arg
        elif opt == "-i":
            IDENTITY = arg
        elif opt == "-f":
            IOCFILE = arg
        elif opt == "-o":
            OUTFILEPREFIX = arg
        elif opt == "-v":
            VERBOSE = 1

    print("---------------------")
    print("TITLE: " + TITLE)
    print("DESCRIPTION: " + DESCRIPTION)
    print("IDENTITY: " + IDENTITY)
    print("IOC FILE: " + IOCFILE)
    print("---------------------")

    ########################
    # Commond data
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    ########################
    # Build STIX 1.2 file
    info_src = InformationSource()
    info_src.identity = Identity(name=IDENTITY)

    NAMESPACE = Namespace("https://infosharing.cybersaiyan.it", "CYBERSAIYAN")
    set_id_namespace(NAMESPACE)

    wrapper = STIXPackage()

    marking_specification = MarkingSpecification()
    marking_specification.controlled_structure = "//node() | //@*"
    tlp = TLPMarkingStructure()
    tlp.color = "white"
    marking_specification.marking_structures.append(tlp)

    handling = Marking()
    handling.add_marking(marking_specification)

    wrapper.stix_header = STIXHeader(information_source=info_src,
                                     title=TITLE,
                                     description=DESCRIPTION,
                                     short_description=SHORT)
    wrapper.stix_header.handling = handling

    # HASH indicators
    indicatorHASH = Indicator()
    indicatorHASH.title = TITLE + " - HASH"
    indicatorHASH.add_indicator_type("File Hash Watchlist")

    # DOMAIN indicators
    indiDOMAIN = Indicator()
    indiDOMAIN.title = TITLE + " - DOMAIN"
    indiDOMAIN.add_indicator_type("Domain Watchlist")

    # URL indicators
    indiURL = Indicator()
    indiURL.title = TITLE + " - URL"
    indiURL.add_indicator_type("URL Watchlist")

    # IP indicators
    indiIP = Indicator()
    indiIP.title = TITLE + " - IP"
    indiIP.add_indicator_type("IP Watchlist")

    # EMAIL indicators
    indiEMAIL = Indicator()
    indiEMAIL.title = TITLE + " - EMAIL"
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
    marking_def_white = stix2.TLP_WHITE

    # campagna
    # [TODO] aggiungere tutti i campi dello STIX 1.2 (es. IDENTITY)
    campaign_MAIN = stix2.Campaign(
        created=timestamp,
        modified=timestamp,
        name=TITLE,
        description=DESCRIPTION,
        first_seen=timestamp,
        objective="TBD"
    )

    ########################
    # Read IoC file
    loaddata(IOCFILE)

    if (VERBOSE): print("Reading IoC file " + IOCFILE + "...")
    ioccount = 0

    # sha256
    for ioc in listSHA256:
        # STIX 1.2
        filei = File()
        filei.add_hash(Hash(ioc))

        obsi = Observable(filei)
        indicatorHASH.add_observable(obsi)
        if (VERBOSE): print("SHA256: " + ioc)

        ioccount += 1

        # STIX 2
        pattern_sha256.append("[file:hashes.'SHA-256' = '" + ioc + "'] OR ")

    # md5
    for ioc in listMD5:
        # STIX 1.2
        filej = File()
        filej.add_hash(Hash(ioc))

        obsj = Observable(filej)
        indicatorHASH.add_observable(obsj)
        if (VERBOSE): print("MD5: " + ioc)

        ioccount += 1

        # STIX 2
        pattern_md5.append("[file:hashes.'MD5' = '" + ioc + "'] OR ")

    # sha1
    for ioc in listSHA1:
        # STIX 1.2
        filek = File()
        filek.add_hash(Hash(ioc))

        obsk = Observable(filek)
        indicatorHASH.add_observable(obsk)
        if (VERBOSE): print("SHA1: " + ioc)

        ioccount += 1

        # STIX 2
        pattern_sha1.append("[file:hashes.'SHA1' = '" + ioc + "'] OR ")

    # domains
    for ioc in listDOMAIN:
        # STIX 1.2
        url = URI()
        url.value = ioc
        url.type_ = URI.TYPE_DOMAIN
        url.condition = "Equals"

        obsu = Observable(url)
        indiDOMAIN.add_observable(obsu)
        if (VERBOSE): print("DOMAIN: " + ioc)

        ioccount += 1

        # STIX 2
        pattern_domain.append("[domain-name:value = '" + ioc + "'] OR ")

    # url
    for ioc in listURL:
        # STIX 1.2
        url = URI()
        url.value = ioc
        url.type_ = URI.TYPE_URL
        url.condition = "Equals"

        obsu = Observable(url)
        indiURL.add_observable(obsu)
        if (VERBOSE): print("URL: " + ioc)

        ioccount += 1

        # STIX 2
        pattern_url.append("[url:value = '" + ioc + "'] OR ")

    # ip
    for ioc in listIP:
        # STIX 1.2
        ip = Address()
        ip.address_value = ioc

        obsu = Observable(ip)
        indiIP.add_observable(obsu)
        if (VERBOSE): print("IP: " + ioc)

        ioccount += 1

        # STIX 2
        pattern_ip.append("[ipv4-addr:value = '" + ioc + "'] OR ")

    # email
    for ioc in listEMAIL:
        # STIX 1.2
        email = EmailAddress()
        email.address_value = ioc

        obsu = Observable(email)
        indiEMAIL.add_observable(obsu)

        if (VERBOSE): print("Email: " + ioc)
        ioccount += 1

        # STIX 2
        pattern_email.append("[email-message:from_ref.value = '" + ioc + "'] OR ")

    # subject
    for ioc in listSUBJECT:
        # STIX 1.2
        emailsubject = EmailMessage()
        emailsubject.subject = ioc

        obsu = Observable(emailsubject)
        indiEMAIL.add_observable(obsu)

        if (VERBOSE): print("Subject: " + ioc)
        ioccount += 1

        # STIX 2 (http://docs.oasis-open.org/cti/stix/v2.0/stix-v2.0-part5-stix-patterning.html)
        # Replace all quotes in a subject string with escaped quotes
        pattern_email.append("[email-message:subject = '" + ioc.replace("'", "\\'") + "'] OR ")

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

    if len(pattern_sha256) != 0:
        stix2_sha256 = "".join(pattern_sha256)
        stix2_sha256 = stix2_sha256[:-4]

        indicator_SHA256 = stix2.Indicator(
            name=TITLE + " - SHA256",
            created=timestamp,
            modified=timestamp,
            description=DESCRIPTION,
            labels=["malicious-activity"],
            pattern=stix2_sha256,
            object_marking_refs=[marking_def_white]
        )
        relationship_indicator_SHA256 = stix2.Relationship(indicator_SHA256, "indicates", campaign_MAIN)
        bundle_objects.append(indicator_SHA256)
        bundle_objects.append(relationship_indicator_SHA256)

    if len(pattern_md5) != 0:
        stix2_md5 = "".join(pattern_md5)
        stix2_md5 = stix2_md5[:-4]

        indicator_MD5 = stix2.Indicator(
            name=TITLE + " - MD5",
            created=timestamp,
            modified=timestamp,
            description=DESCRIPTION,
            labels=["malicious-activity"],
            pattern=stix2_md5,
            object_marking_refs=[marking_def_white]
        )
        relationship_indicator_MD5 = stix2.Relationship(indicator_MD5, "indicates", campaign_MAIN)
        bundle_objects.append(indicator_MD5)
        bundle_objects.append(relationship_indicator_MD5)

    if len(pattern_sha1) != 0:
        stix2_sha1 = "".join(pattern_sha1)
        stix2_sha1 = stix2_sha1[:-4]

        indicator_SHA1 = stix2.Indicator(
            name=TITLE + " - SHA1",
            created=timestamp,
            modified=timestamp,
            description=DESCRIPTION,
            labels=["malicious-activity"],
            pattern=stix2_sha1,
            object_marking_refs=[marking_def_white]
        )
        relationship_indicator_SHA1 = stix2.Relationship(indicator_SHA1, "indicates", campaign_MAIN)
        bundle_objects.append(indicator_SHA1)
        bundle_objects.append(relationship_indicator_SHA1)

    if len(pattern_domain) != 0:
        stix2_domain = "".join(pattern_domain)
        stix2_domain = stix2_domain[:-4]

        indicator_DOMAINS = stix2.Indicator(
            name=TITLE + " - DOMAINS",
            created=timestamp,
            modified=timestamp,
            description=DESCRIPTION,
            labels=["malicious-activity"],
            pattern=stix2_domain,
            object_marking_refs=[marking_def_white]
        )
        relationship_indicator_DOMAINS = stix2.Relationship(indicator_DOMAINS, "indicates", campaign_MAIN)
        bundle_objects.append(indicator_DOMAINS)
        bundle_objects.append(relationship_indicator_DOMAINS)

    if len(pattern_url) != 0:
        stix2_url = "".join(pattern_url)
        stix2_url = stix2_url[:-4]

        indicator_URLS = stix2.Indicator(
            name=TITLE + " - URL",
            created=timestamp,
            modified=timestamp,
            description=DESCRIPTION,
            labels=["malicious-activity"],
            pattern=stix2_url,
            object_marking_refs=[marking_def_white]
        )
        relationship_indicator_URLS = stix2.Relationship(indicator_URLS, "indicates", campaign_MAIN)
        bundle_objects.append(indicator_URLS)
        bundle_objects.append(relationship_indicator_URLS)

    if len(pattern_ip) != 0:
        stix2_ip = "".join(pattern_ip)
        stix2_ip = stix2_ip[:-4]

        indicator_IPS = stix2.Indicator(
            name=TITLE + " - IPS",
            created=timestamp,
            modified=timestamp,
            description=DESCRIPTION,
            labels=["malicious-activity"],
            pattern=stix2_ip,
            object_marking_refs=[marking_def_white]
        )
        relationship_indicator_IPS = stix2.Relationship(indicator_IPS, "indicates", campaign_MAIN)
        bundle_objects.append(indicator_IPS)
        bundle_objects.append(relationship_indicator_IPS)

    if len(pattern_email) != 0:
        stix2_email = "".join(pattern_email)
        stix2_email = stix2_email[:-4]

        indicator_EMAILS = stix2.Indicator(
            name=TITLE + " - EMAILS",
            created=timestamp,
            modified=timestamp,
            description=DESCRIPTION,
            labels=["malicious-activity"],
            pattern=stix2_email,
            object_marking_refs=[marking_def_white]
        )
        relationship_indicator_EMAILS = stix2.Relationship(indicator_EMAILS, "indicates", campaign_MAIN)
        bundle_objects.append(indicator_EMAILS)
        bundle_objects.append(relationship_indicator_EMAILS)

    # creo il bunble STIX 2
    bundlestix2 = stix2.Bundle(objects=bundle_objects)

    if (ioccount > 0):
        ########################
        # save to STIX 1.2 file
        print("Writing STIX 1.2 package: " + OUTFILEPREFIX + ".stix")
        f = open(OUTFILEPREFIX + ".stix", "wb")
        f.write(wrapper.to_xml())
        f.close()

        ########################
        # save to STIX 2 file
        print("Writing STIX 2 package: " + OUTFILEPREFIX + ".stix2")
        g = open(OUTFILEPREFIX + ".stix2", "w")
        g.write(str(bundlestix2))
        g.close()
    else:
        print("No IoC found")


if __name__ == "__main__":
    main(sys.argv[1:])
    sys.exit(0)
