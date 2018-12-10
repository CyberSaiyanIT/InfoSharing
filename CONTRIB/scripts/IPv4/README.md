# How to 

Aggiornare il contenuto di "example_data_ip.json" con i dati che si desidera condividere:

* "NSXURL": La URL del namespace
* "NS" : Il NAMESPECE scelto
* "Title": Il titolo del report, come chiave per la minaccia rispetto a quello che ci siamo detti
* "Description": La descrizione
* "Identity": L'identità di chi ha prodotto il report
* "IoC" : Vedi paragrafo IoC
* "TLP_COLOR": a scelta fra "WHITE", "GREEN", "AMBER", "RED"

## IoC

Array multidimensionale, avente come chiave il FQDN da segnalare in lista e come elementi, gli hash dei file che si riferiscono a quella minaccia.
L'elemento primario del Array è quindi una lista, avente chiave il nome a dominio. Anche se la lista è vuota, l'elemento va rappresentato come lista.

Esempio

```
IOC": 	{
	"10.10.10.10":["5f0ffd98d4a68953caefbb55c5f2f250"],
	"10.10.10.11":[]
	}
```
Nel primo caso l'IP "10.10.10.10 avrà in IoC related con MD5 "5f0ffd98d4a68953caefbb55c5f2f250".

Nel secondo caso, verrà indicato come malevolo solo l'IP "10.10.10.11" senza hash relazionati.

## Dopo eseguire il seguente comando:

`python Report_IP_Producer.py example_data_ip.json`

### Requisiti:
* stix==1.1.1.4
* cybox==2.1.0.12

```
~$ git clone https://github.com/CybOXProject/python-cybox.git
~$ cd python-cybox/
~$ git checkout v2.1.0.12
~$ sudo python setup.py install

~$ cd ..

~$ git clone https://github.com/STIXProject/python-stix.git
~$ cd python-stix
~$ git checkout v1.1.1.4
~$ sudo python setup.py install 
```
