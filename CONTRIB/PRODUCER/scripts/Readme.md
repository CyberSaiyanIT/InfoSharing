# Script PRODUCER

## Generazione formati STIX 1.2 e 2
Lo script python CS\_build\_stix-from\_files.py legge un file di testo contenente gli IoC (hash, domain, url, ip, email) e genera i file STIX 1.2 e STIX 2 pronti da iniettare sulla rete STIX/TAXII della community Cyber Saiyan

Per poter utilizzare lo script è necessario installare le seguenti dipendenze (testato su Ubuntu >= 18.04)
```
# cabby 
pip install cabby

# python-cybox
git clone https://github.com/CybOXProject/python-cybox.git
cd python-cybox/
~$ sudo python setup.py install

# python-stix
git clone https://github.com/STIXProject/python-stix.git
cd python-stix
sudo python setup.py install 

# stix
pip install stix
pip install stix2

# validators
pip install validators
```

Prima di eseguire lo script effettuare le seguenti operazioni
* aggiornare le variabili MyTITLE, DESCRIPTION, IDENTITY
* fare un clear del file CS-ioc.txt (~$ > CS-ioc.txt)
* inserire gli IoC supportati (sha256, sha1, md5, domain, ipv4, url) nel file CS-ioc.txt. Lo script parsa il file linea per linea e usa delle espressioni regolari per validare gli IoC, commenti o IoC malformati vengono ignorati
* eseguire lo script 
```
python -W ignore CS_build_stix.py
```

Dopo l'esecuzione vengono generati due file (vedi esempi nella dir)
* package.stix: file STIX 1.2 (XML)
* package.stix2: file STIX 2 (JSON)

Dopo aver creato i file STIX è possibile fare il PUSH (via Cabby in questo esempio) del file STIX 1.2 (unico formato supportato al momento) sulla rete STIX/TAXII della community con il seguente comando (la password per il push deve essere richiesta sul gruppo Telegram dedicato)
```
taxii-push --discovery https://infosharing.cybersaiyan.it:9000/services/discovery --dest community --username community --password <TO-BE-SENT> --content-file package.stix
```

La verifica del caricamento può essere fatta con Cabby (tempo massimo di update 10 minuti)
```
taxii-poll --host infosharing.cybersaiyan.it --https --collection CS-COMMUNITY-TAXII --discovery /taxii-discovery-service
```
