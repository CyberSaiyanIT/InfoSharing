SETUP
====================================
chmod +x Report_FQDN_Producer.py


USAGE
====================================
./Report_FQDN_Producer.py example_data_fqdn.json


HOW TO per JSON
====================================
Modificare il file JSON nelle seguenti chiavi, così come descritto dal file di esempio stesso:
"NSXURL": "LA URL DEL NAMESPACE",
"NS" : "Il NAMESPECE scelto",
"Title": "Il titolo del report, come chiave per la minaccia rispetto a quello che ci siamo detti",
"Identity": "L'identità di chi ha prodotto il report"
"TLP_COLOR": a scelta fra "WHITE", "GREEN", "AMBER", "RED"

IMPORTANTE
Elemento "IOC"
Array multidimensionale, avente come chiave il FQDN da segnalare in lista e come elementi, gli hash dei file che si riferiscono a quella minaccia.
L'elemento primario del Array è quindi una lista, avente chiave il nome a dominio. Anche se la lista è vuota, l'elemento va rappresentato come lista.

Esempio

```
IOC": 	{
	"239outdoors.com":["5f0ffd98d4a68953caefbb55c5f2f250"],
	"bentlabel.com":[]
	}
```

Nel primo caso il dominio "239outdoors.com" avrà in IoC related con MD5 "5f0ffd98d4a68953caefbb55c5f2f250".
Nel secondo caso, verrà indicato come malevolo solo il dominio "bentlabel.com" senza hash relazionati.
