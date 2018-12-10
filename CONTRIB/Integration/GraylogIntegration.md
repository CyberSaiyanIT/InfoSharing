# GRAYLOG INTEGRATION
L'integrazione con Graylog è stata eseguita sfruttando le funzionalità pipeline e lookup tables integrate in graylog stesso. Per questioni di semplicità e rapidità di esecuzione si è scelto di effettuare il download localmente del file CSV esposto da minemeld (N.B. in installazione cluster di graylog tale file deve essere presente su tutti i nodi nella medesima directory) ed effettuare dei lookup puntuali in fase di ricezione del messaggio.  
Di seguito viene riportato uno schema dell'architettura.

![l'architettura della pipeline](/img/m2gl_ARCHITECTURE.png)


![l'architettura della pipeline](/img/Pipeline&#32;Diagram.png)
