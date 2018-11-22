# InfoSharing
Questo repository traccia le attività del gruppo operativo per la sperimentazione di un meccanismo di Info Sharing della community [Cyber Saiyan](https://www.cybersaiyan.it)

Il gruppo è stato avviato a seguito di una web conf tenuta il giorno 8 Novembre 2018 il cui [resoconto è disponibile qui](https://docs.google.com/document/d/13PCWGlVvdOy226GXaWcnzkvl-7WfCyIUXTYGknrd9bg/edit).

L'obiettivo è quello di creare una community italiana che funzioni da collettore degli indicatori "pregiati" già disponibili e condivisi da fonti autorevoli (get di indicatori) e al contempo possa contribuire con le proprie expertise all'arricchimento della rete di condivisione (push indicatori sulla rete). 

Come punto di partenza è stata integrata la piattaforma [InfoSec del CERT-PA](https://infosec.cert-pa.it) da cui si raccolgono  IoC (Indicator of Compromise) del tipo IP, domini, URL.

Le varie componenti del servizio che si sta costruendo sono accessibili all'indirizzo https://infosharing.cybersaiyan.it ed al momento includono l'export degli IoC nei seguenti formati
* [STIX/TAXII](IoC-STIX_TAXII.md)
* [testo](IoC-text.md)

La guida all'installazione del server è [disponibile qui](INSTALL-Server_software.md)
