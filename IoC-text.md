E' possibile recuperare gli IoC anche in formato testuale usando l'endpoint dedicato
https://infosharing.cybersaiyan.it/feeds/CS-HTTP

Utilizzando Minemeld per la pubblicazione, questi dati si possono "manipolare" usando parametri GET che sono [descritti qui](https://live.paloaltonetworks.com/t5/MineMeld-Articles/Parameters-for-the-output-feeds/ta-p/146170) (es. export in CSV, field particolari etc)

###Esempio
E' possibile usare il formato CSV per integrare gli IoC nelle search SPLUNK
https://infosharing.cybersaiyan.it/feeds/CS-HTTP?v=csv&f=type&f=indicator&tr=1

Si esporta un file CSV con riga di intestazione _type,indicator_ dove
* _type_ è il tipo di IoC (es. domain, URL, IPv4)
* _indicator_ è l'IoC
