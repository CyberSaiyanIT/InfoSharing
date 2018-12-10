# GRAYLOG INTEGRATION
L'integrazione con Graylog è stata eseguita sfruttando le funzionalità pipeline e lookup tables integrate in graylog stesso. Per questioni di semplicità e rapidità di esecuzione si è scelto di effettuare il download localmente del file CSV esposto da minemeld (N.B. in installazione cluster di graylog tale file deve essere presente su tutti i nodi nella medesima directory) ed effettuare dei lookup puntuali in fase di ricezione del messaggio.  
Di seguito viene riportato uno schema dell'architettura.


![l'architettura della pipeline](/img/m2gl_ARCHITECTURE.png)



Per il download del CSV è utilizzato uno script bask originariamente sviluppato da Giovanni Mellini [LINK](https://scubarda.com/2017/08/11/minemeld-threat-intelligence-automation-foundation-write-a-custom-prototype-and-soc-integration/) e leggermente riadattato [LINK](InfoSharing/CONTRIB/scripts/csvdropper.sh), lo script effettua il download del file CSV in una directory temporanea con il nome indicato nella variabile filename e poi lo sposta nella directory indicata nella variabile dir, entrambe le fariabili sono da customizzare in base al contesto di installazione.
Una volta effettuato il download del file CSV occorre creare una funzione in una pipeline che crea un nuovo campo in caso di match tra l'indirizzo ip (sorgente o destinazione) e un'entry nel CSV appena scaricato.
(N.B. in questo use case è stata applicata la pipeline ad uno stream contenente i messaggi provenienti da firewall)


![l'architettura della pipeline](/img/Pipeline&#32;Diagram.png)


La pipeline deve essere connessa allo stream contenete i messaggi che si vogliono arricchire (ad esempio firewall) 


![l'architettura della pipeline](/img/Pipeline_details.JPG)


Il lookup avviene tramite l'apposita funzione nella pipeline, è necessario definire prima la tabella di lookup e il relativo data adapter. Di seguito vengono mostrati entrambi:


![l'architettura della pipeline](/img/DataAdapter.JPG)


![l'architettura della pipeline](/img/lookuptable.JPG)
