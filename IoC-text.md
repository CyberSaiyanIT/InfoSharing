# Endpoint disponibili
Per recuperare gli IoC sono disponibili vari endopoint
* https://infosharing.cybersaiyan.it/feeds/CS-COMMUNITY-HTTP : lista di tutti gli IoC disponibili (IP, domini, URL, email, HASH)
* https://infosharing.cybersaiyan.it/feeds/CS-PIHOLE : lista degli IoC di tipo dominio; utile per integrazione con [PiHole](https://pi-hole.net/)
* https://infosharing.cybersaiyan.it/feeds/CS-IP : lista degli IoC di tipo ip; utile per integrazione con liste di blocco su firewall

# Output
L'output del feed può essere manipolato usando i parametri [descritti qui](https://live.paloaltonetworks.com/t5/MineMeld-Articles/Parameters-for-the-output-feeds/ta-p/146170) ed è quindi possibile ottenere vari outut a seconda delle esigenze

NOTA: gli esempi seguenti usano l'endpoint ```CS-COMMUNITY-HTTP```

## Testo semplice
Connettersi alla URL

https://infosharing.cybersaiyan.it/feeds/CS-COMMUNITY-HTTP?tr=1

L'opzione ```tr=1``` normalizza gli indirizzi IP in formato CIDR

## CSV
Connettersi alla URL

https://infosharing.cybersaiyan.it/feeds/CS-COMMUNITY-HTTP?v=csv&f=type&f=indicator&tr=1

Si esporta un file CSV con riga di intestazione _type,indicator_ dove
* _type_ è il tipo di IoC (es. domain, URL, IPv4)
* _indicator_ è l'IoC

Il formato CSV può essere usato per integrare gli IoC nelle search SPLUNK ([vedi qui per dettagli](https://scubarda.com/2017/09/12/minemeld-threat-intelligence-automation-analyze-received-ioc-with-splunk-4/))

## JSON
Connettersi alla URL

https://infosharing.cybersaiyan.it/feeds/CS-COMMUNITY-HTTP?v=json
