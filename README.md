# Info Sharing
Questo repository traccia le attività del gruppo operativo per la sperimentazione di un meccanismo di Info Sharing della community [Cyber Saiyan](https://www.cybersaiyan.it) avviato a Novembre 2018.

L'obiettivo è quello di creare una community italiana che funzioni da collettore di indicatori di compromissione (IoC) disponibili e condivisi da fonti autorevoli (GET di indicatori) e che al contempo possa contribuire con le proprie expertise all'arricchimento della rete di condivisione (PUSH indicatori sulla rete) o alla validazione degli indicatori.

Oggi è implementata la seguente architettura che prevede due componenti distinte
* la componente PRODUCER: realizzata attraverso il software [OpenTAXII](http://www.opentaxii.org/en/stable/) su cui è stata configurata una collection denominata _community_ su cui è abilitato il PUSH autenticato di IoC in formato STIX 1.2
* la componente CONSUMER: realizzata attraverso il software [Minemeld](https://www.paloaltonetworks.com/products/secure-the-network/subscriptions/minemeld) che effettua periodicamente il POLL degli IoC dalla collection _community_ di OpenTAXII e "ribalta" tali indicatori su due feed distinti (testo e STIX/TAXII)

![l'architettura implementata](img/architettura.png)

## Componente CONSUMER
Gli indicatori sono accessibili in vari formati
* formato STIX/TAXII
   * formato [STIX 1.2 over TAXII 1.1](IoC-STIX_TAXII.md#stix-12-over-taxii-11): IoC completi di informazioni di contesto (originatore, minaccia e descrizione)
   * formato [STIX 2 over TAXII 2](IoC-STIX_TAXII.md#stix-2-over-taxii-2): IoC senza le informazioni di contesto
* formato [TESTO / CSV / JSON](IoC-text.md): IoC senza le informazioni di contesto

Qui di seguito alcuni esempi di integrazione
* [Come integrare MISP](https://github.com/patriziotufarolo/cybersaiyan-taxii2misp): integrazione del feed STIX nella piattaforma open source [TIP MISP](https://www.misp-project.org/), tks @patriziotufarolo
* [Come integrare MINEMELD](https://scubarda.com/2018/03/31/minemeld-threat-intelligence-automation-connect-to-an-taxii-service/): seguire le indicazioni del post per integrare il feed STIX in [Minemeld](https://www.paloaltonetworks.com/products/secure-the-network/subscriptions/minemeld); impostare i seguenti valori nel miner ```taxiing.phishtank```
    * _collection_: ```CS-COMMUNITY-TAXII```
    * _discovery_service_: ```https://infosharing.cybersaiyan.it/taxii-discovery-service```
    * _username_/_password_: NON IMPOSTARE, la connessione è non autenticata
* [Come integrare GRAYLOG](/CONTRIB/CONSUMER/Graylog/): integrazione del feed in [Graylog](https://www.graylog.org/)

## Componente PRODUCER
La componente PRODUCER è alimentata **da utenti autorizzati**
* dall'interfaccia web all'indirizzo [https://infosharing.cybersaiyan.it/producer/](https://infosharing.cybersaiyan.it/producer/) 
* [generando i file STIX](/CONTRIB/PRODUCER/scripts/) che poi vanno caricati (PUSH) sul server OpenTAXII

## Architettura
La guida all'installazione del server e del software di base è [disponibile qui](INSTALL/Server_software.md).
Le configurazioni dei software (OpenTAXII e Minemeld) saranno descritte in seguito [TODO].

## Community
Il progetto è un'iniziativa volontaria portata avanti dalla community di Cyber Saiyan.
E' stato creato un [gruppo Telegram](https://t.me/joinchat/Av4DDFjVkRC60YH_Lq-WVw) per coordinare l'evoluzione del progetto.
