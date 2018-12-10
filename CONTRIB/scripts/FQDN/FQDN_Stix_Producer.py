#!/usr/bin/env python
import sys 
import os.path 
import json 
import time 
import datetime 
from stix.core import STIXPackage, STIXHeader 
from stix.data_marking import Marking, MarkingSpecification 
from stix.extensions.marking.tlp import TLPMarkingStructure 
from mixbox.idgen import set_id_namespace
from mixbox.namespaces import Namespace 
from stix.common import InformationSource, Identity 
from stix.indicator import Indicator 
from cybox.core import Observable 
from cybox.common import Hash 
from cybox.objects.file_object import File 
from cybox.objects.uri_object import URI 
from cybox.objects.address_object import Address 

def fileexists():
    return os.path.exists(sys.argv[1]) 

def loaddata():
    if fileexists:
        with open(sys.argv[1]) as data_file:
            try:
                data = json.load(data_file)
                return data
            except ValueError, error:
                return exit("Not a valid JSON:" + sys.argv[1])

def sanitizer(s):
    return s.strip(' \t\n\r')
    
def main():
    mydata = loaddata()
    '''
    Your Namespace
    '''
#    NAMESPACE = {sanitizer(mydata["NSXURL"]) : sanitizer(mydata["NS"])}
#    set_id_namespace(NAMESPACE)
    NAMESPACE = Namespace(sanitizer(mydata['NSXURL']), sanitizer(mydata['NS']))
    set_id_namespace(NAMESPACE) # new ids will be prefixed by "myNS"

    wrapper = STIXPackage()
    info_src = InformationSource()
    info_src.identity = Identity(name=sanitizer(mydata["Identity"]))
    
    marking_specification = MarkingSpecification()
    marking_specification.controlled_structure = "//node() | //@*"
    tlp = TLPMarkingStructure()
    tlp.color = sanitizer(mydata["TLP_COLOR"])
    marking_specification.marking_structures.append(tlp)
    
    handling = Marking()
    handling.add_marking(marking_specification)
    
    timestamp = datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')
    
    MyTITLE = sanitizer(mydata["Title"])
    SHORT = timestamp
    
    DESCRIPTION = sanitizer(mydata["Description"])
    wrapper.stix_header = STIXHeader(information_source=info_src, title=MyTITLE, description=DESCRIPTION, short_description=SHORT)
    wrapper.stix_header.handling = handling
    indiDom = Indicator()
    indiDom.title = MyTITLE
    indiDom.add_indicator_type("Domain Watchlist")
    for key in mydata["IOC"].keys():
        fqdn = URI() 
	fqdn.value = sanitizer(key) 
	fqdn.type_ = URI.TYPE_DOMAIN 
	fqdn.condition = "Equals"
        
        obsu = Observable(fqdn)
        
        for idx, mydata["IOC"][key] in enumerate(mydata["IOC"][key]):
            ioc = File()
            ioc.add_hash(sanitizer(mydata["IOC"][key]))

            fqdn.add_related(ioc, "Downloaded")

        indiDom.add_observable(obsu)

    wrapper.add_indicator(indiDom)
  
    print(wrapper.to_xml())
 
if __name__ == '__main__':
    main()
