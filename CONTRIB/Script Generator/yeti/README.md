# Template Jinja2 per [Yeti](https://github.com/yeti-platform/yeti)

Export template per precompilare observable di yeti nello script python di merlos.

## Utilizzo template

- Tagga gli observable per tipo con i tag `sha256` `sha1` `md5` `email` `domain` `ip` `url`
- Modifica titolo, descrizione e identity nel testo del template
- Copia-incolla in un export template di yeti [come da doc](https://yeti-platform.readthedocs.io/en/latest/use-cases.html#creating-an-export-template)
- Fai una query ed esporta gli observable corrispondenti con il template creato per ottenere lo script.


## Utilizzo script


 ### Requirements

 - cabby

    `pip install cabby`

 - cybox

    `pip install cybox`

 - stix

    `pip install stix`

 - validators

    `pip install validators`


 ### PUSH degli IoC sulla rete Cyber Saiyan

 - Generazione del file STIX da pushare successivamente sulla rete (file: package.stix)

   `python -W ignore yeti_xxxx.txt`

 - PUSH via Cabby del file package.stix sulla collection dedicata "community" (la password per il push deve essere richiesta sul gruppo Telegram dedicato)

    `taxii-push --discovery https://infosharing.cybersaiyan.it:9000/services/discovery --dest community --username community --password <TO-BE-SENT> --content-file package.stix`

 - Verifica via Cabby degli IoC (tempo di aggiornamento massimo 10 minuti)

    `taxii-poll --host infosharing.cybersaiyan.it --https --collection CS-COMMUNITY-TAXII --discovery /taxii-discovery-service`
