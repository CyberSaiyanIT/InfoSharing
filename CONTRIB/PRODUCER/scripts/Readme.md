# Script PRODUCER

## Generazione formati STIX 1.2 e 2
Lo script python ```CS_build_stix-from_files.py``` legge un file di testo contenente gli IoC (sha256, sha1, md5, domain, url, ip, email) e genera i file STIX 1.2 (XML) e STIX 2 (JSON) da caricare (PUSH) sulla rete STIX/TAXII della community Cyber Saiyan (al momento la rete supporta esclusivamente il formato STIX 1.2)

Per poter utilizzare lo script è necessario usare ```python3``` ed installare le seguenti dipendenze (testato su Ubuntu Server LTS 16.04, 18.04 e MacOS). 
È consigliato - almeno per una fase iniziale di test e sperimentazione - utilizzare un [virtual environment python](https://docs.python.org/3/library/venv.html)

```
# cabby 
sudo pip3 install cabby

# stix
sudo pip3 install stix #già installato come dipendenza cabby, just for...
sudo pip3 install stix2

# validators
sudo pip3 install validators
```

Prima di eseguire lo script effettuare le seguenti operazioni
* nel file ```CS_build_stix-from_files.py``` aggiornare le variabili TITLE, DESCRIPTION, IDENTITY; è possibile impostare i tre parametri anche da riga di comando usando le opzioni -t, -d e -i: ```CS_build_stix-from_files.py [-t TITLE] [-d DESCRIPTION] [-i IDENTITY]```
* editare il file ```CS-ioc.txt``` ed inserire la lista degli IoC supportati (sha256, sha1, md5, domain, ipv4, url). Lo script parsa il file linea per linea ed usa delle espressioni regolari per validare gli IoC; commenti o IoC malformati vengono ignorati. Nel caso in cui si voglia leggere un file differente usare l'opzione -f ```CS_build_stix-from_files.py [-f IOC_FILE]```

A questo punto si esegue lo script
* senza opzioni ```python3 -W ignore CS_build_stix-from_files.py```; usa i valori delle variabili TITLE, DESCRIPTION, IDENTITY definite nello script e legge il file ```CS-ioc.txt```
* con opzioni ```python3 -W ignore CS_build_stix-from_files.py [-t TITLE] [-d DESCRIPTION] [-i IDENTITY] [-f IOC_FILE] [-o STIX_FILES_PREFIX]```; sovrascrive le impostazioni predefinite

In output lo script genera due file STIX il cui nome può essere cambiato usando l'opzione -o ```CS_build_stix-from_files.py [-o STIX_FILES_PREFIX]```
* ```package.stix```: file STIX 1.2 [XML](/CONTRIB/PRODUCER/scripts/package.stix)
* ```package.stix2```: file STIX 2 [JSON](/CONTRIB/PRODUCER/scripts/package.stix2)

## PUSH STIX 1.2
Dopo aver creato i file STIX è necessario fare il PUSH (via Cabby in questo esempio) del file STIX 1.2 (unico formato supportato al momento) sulla rete STIX/TAXII della community Cyber Saiyan.
Di seguito il comando da eseguire che richiede una password (il PUSH è autenticato); nel caso in cui si volesse contribuire unirsi al [gruppo Telegram](https://t.me/joinchat/Av4DDFjVkRC60YH_Lq-WVw)
```
taxii-push --discovery https://infosharing.cybersaiyan.it:9000/services/discovery --dest community --username community --password <TO-BE-SENT> --content-file package.stix
```

La verifica dell'effettivo caricamento degli IoC sulla rete può essere fatta con Cabby in maniera non autenticata (tempo massimo di update 10 minuti)
```
taxii-poll --host infosharing.cybersaiyan.it --https --collection CS-COMMUNITY-TAXII --discovery /taxii-discovery-service
```
