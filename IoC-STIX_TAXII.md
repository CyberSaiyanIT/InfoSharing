Per poter recuperare gli IoC in formato STIX è possibile [installare il software Cabby](https://cabby.readthedocs.io/en/stable/installation.html)

Di seguito la procedura testata su Ubuntu >=18.04
```
sudo apt install virtualenv
virtualenv cabby
. cabby/bin/activate
```
a questo punto la shell sarà nella forma
```
(cabby) gmellini@18-10:~$
```
e si potrà installare il software via pip
```
pip install cabby
```
Una volta installato cabby si procede alla connessione al servizio STIX/TAXXI erogato sul serverinfosharing.cybersaiyan.it

### Fase di Discovery
La fase iniziale è quella di discovery dei servizii erogati dal server STIX/TAXII infosharing.cybersaiyan.it
Per questo si usa il comando _taxii-discovery_ con gli opportuni parametri (la lista è disponbile all'indirizzo /taxii-discovery-service)
```
taxii-discovery --host infosharing.cybersaiyan.it --path /taxii-discovery-service --https
```
L'ouput del comando riporta i servizi disponili
* DISCOVERY
* COLLECTION_MANAGEMENT
* POLL
```
(cabby) gmellini@18-10:~$ taxii-discovery --host infosharing.cybersaiyan.it --path /taxii-discovery-service --https
2018-11-22 15:03:24,459 INFO: Sending Discovery_Request to https://infosharing.cybersaiyan.it/taxii-discovery-service
2018-11-22 15:03:25,323 INFO: 3 services discovered
=== Service Instance ===
  Service Type: DISCOVERY
  Service Version: urn:taxii.mitre.org:services:1.1
  Protocol Binding: urn:taxii.mitre.org:protocol:http:1.0
  Service Address: https://infosharing.cybersaiyan.it/taxii-discovery-service
  Message Binding: urn:taxii.mitre.org:message:xml:1.1
  Available: True
  Message: None

=== Service Instance ===
  Service Type: COLLECTION_MANAGEMENT
  Service Version: urn:taxii.mitre.org:services:1.1
  Protocol Binding: urn:taxii.mitre.org:protocol:http:1.0
  Service Address: https://infosharing.cybersaiyan.it/taxii-collection-management-service
  Message Binding: urn:taxii.mitre.org:message:xml:1.1
  Available: True
  Message: None

=== Service Instance ===
  Service Type: POLL
  Service Version: urn:taxii.mitre.org:services:1.1
  Protocol Binding: urn:taxii.mitre.org:protocol:http:1.0
  Service Address: https://infosharing.cybersaiyan.it/taxii-poll-service
  Message Binding: urn:taxii.mitre.org:message:xml:1.1
  Available: True
  Message: None
  ```

### Lista delle Collection disponibili
Si recupera la lista delle Collection disponibili eseguendo il comando _taxii-collections_
```
taxii-collections --path https://infosharing.cybersaiyan.it/taxii-collection-management-service
```
Il comando evidenzia che è disponibile una unica Collection, **CS-TAXII**
```
(cabby) gmellini@18-10:~$ taxii-collections --path https://infosharing.cybersaiyan.it/taxii-collection-management-service
  === Data Collection Information ===
  Collection Name: CS-TAXII
  Collection Type: DATA_FEED
  Available: True
  Collection Description: CS-TAXII Data Feed
  Supported Content:   urn:stix.mitre.org:xml:1.1.1
  === Polling Service Instance ===
    Poll Protocol: urn:taxii.mitre.org:protocol:http:1.0
    Poll Address: https://infosharing.cybersaiyan.it/taxii-poll-service
    Message Binding: urn:taxii.mitre.org:message:xml:1.1
==================================
```

### Recupero degli IoC dalla Colletion
Il recupero degli indicatori è fatto usando il comando _taxii-poll_
```
taxii-poll --host infosharing.cybersaiyan.it --https --collection CS-TAXII --discovery /taxii-discovery-service
```
```
(cabby) gmellini@18-10:~$ taxii-poll --host infosharing.cybersaiyan.it --https --collection CS-TAXII --discovery /taxii-discovery-service
[...]
lista degli IoC in formato STIX 1.2 (XML)
[...]
```

### Formato di un generico IoC
Di seguito il formato di un generico IoC; i campi principali sono 
* _indicator:Title_ ==> questo deve definire univocamente la minaccia
* _indicator:Description_ ==> descrizione della minaccia/indicatore 
* _indicator:Observable_ ==> in questa sezione sono specificati gli IoC (più di uno anche) associati alla minaccia

E' importante evidenziare che  ci sono anche altri field interessanti che non sono presenti in questi indicatori perchè sono collezionati da file CSV sul sito del CERT-PA
```
    <stix:STIX_Header>
        <stix:Handling>
            <marking:Marking>
                <marking:Controlled_Structure>//node() | //@*</marking:Controlled_Structure>
                <marking:Marking_Structure xsi:type="tlpMarking:TLPMarkingStructureType" color="GREEN"/>
            </marking:Marking>
        </stix:Handling>
    </stix:STIX_Header>
    <stix:Indicators>
        <stix:Indicator id="minemeld:indicator-05f5695b-df5a-4275-8fae-d9af2758880b" timestamp="2018-11-22T11:02:05.361820+00:00" xsi:type="indicator:IndicatorType">
            <indicator:Title>URL: http://sanliurfakarsiyakataksi.com/theme/nafown.jpg</indicator:Title>
            <indicator:Type xsi:type="stixVocabs:IndicatorTypeVocab-1.1">URL Watchlist</indicator:Type>
            <indicator:Description>URL indicator from itcertpa.URLS</indicator:Description>
            <indicator:Observable id="minemeld:observable-c92968e5-8954-4e5b-b05d-0087ac8b2835">
                <cybox:Title>URL: http://sanliurfakarsiyakataksi.com/theme/nafown.jpg</cybox:Title>
                <cybox:Object id="minemeld:URI-d08703da-741d-4f26-b21a-9e9667233b41">
                    <cybox:Properties xsi:type="URIObj:URIObjectType" type="URL">
                        <URIObj:Value>http://sanliurfakarsiyakataksi.com/theme/nafown.jpg</URIObj:Value>
                    </cybox:Properties>
                </cybox:Object>
            </indicator:Observable>
            <indicator:Confidence timestamp="2018-11-22T11:02:05.361943+00:00">
                <stixCommon:Value>High</stixCommon:Value>
            </indicator:Confidence>
        </stix:Indicator>
    </stix:Indicators>
```
