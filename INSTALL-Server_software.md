# Software di base
Nei paragrafi seguenti si riportano i passi di installazione dei software usati sul server infosharing.cybersaiyan.it

### Sistema Operaivo
Il sistema operativo di base è una Ubuntu Server 16.04 LTS scaricabile a questo indirizzo http://releases.ubuntu.com/16.04/

### NGINX
Installare NGINX nella sua configurazione di base
```
sudo apt install nginx
```
NGINX è il reverse proxy che utilizza Minemeld per erogare il servizio

### Minemeld
[Minemeld](https://www.paloaltonetworks.com/products/secure-the-network/subscriptions/minemeld) è il software utilizzato per collezionare IoC da fonti esterne e ripubblicare questi Ioc (normalizzati, deduplicati e storicizzati) in vari formati (STIX/TAXII e testo).

La guida ufficiale all'installazione di Minemeld è disponibile [a questo indirizzo](https://github.com/PaloAltoNetworks/minemeld-ansible#howto-on-ubuntu-1604).

Di seguito tutti gli step di installazione contestualizzati allo scenario in via di sperimentazione.
```
sudo apt-get update
sudo apt-get upgrade

sudo apt-get install -y gcc git python-minimal python2.7-dev libffi-dev libssl-dev make

wget https://bootstrap.pypa.io/get-pip.py
sudo -H python get-pip.py
sudo -H pip install ansible

git clone https://github.com/PaloAltoNetworks/minemeld-ansible.git
cd minemeld-ansible
ansible-playbook -K -e "minemeld_version=master" -i 127.0.0.1, local.yml
```
Verificare lo stato del servizio.
```
sudo service minemeld status
```
Minemeld cambia la configurazione del _default_ site di NGINX e crea il nuovo site _minemeld-web_ 
```
##############################################
# file: /etc/nginx/sites-enabled/minemeld-web

upstream app_server {
    server 127.0.0.1:5000 fail_timeout=0;
}

server {
    listen 80;
    server_name ~(.+)$;
    return 301 https://$1$request_uri;
}

server {
    listen 443 ssl;

    server_name _;
    ssl_certificate /etc/nginx/minemeld.cer;
    ssl_certificate_key /etc/nginx/minemeld.pem;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';

    keepalive_timeout 5;

    # path for static files
    root /opt/minemeld/www/current;

    location = / {
        index index.html;
    }

    location ~* \.html$ {
        try_files $uri @proxy_to_app;
        expires -1;
    }

    # first files then proxy to flask app
    location / {
        try_files $uri @proxy_to_app;
        expires off;
    }

    # for SSE
    location /status/events {
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_set_header Connection '';
        proxy_http_version 1.1;
        proxy_redirect off;
        proxy_buffering off;
        chunked_transfer_encoding off;
        proxy_cache off;
        proxy_read_timeout 120s;

        expires -1;

        proxy_pass   http://app_server;        
    }

    # for content that should be handled by mw flask app
    location @proxy_to_app {
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $http_host;
        proxy_redirect off;

        proxy_pass   http://app_server;
    }
}
```
Da questo momento Minemeld è up&running ed accessibile all'indirizzo locale della macchina (utenza default admin/minemeld) e pronto per essere configurato.

### OpenTAXII
Il server OpenTAXII è utilizzato per consentire alla community il **PUSH degli IoC** e quindi va ad implemetare i meccanismi di **contribuzione**; gli IoC _pushati_ saranno poi ripubblicati in formato STIX/TAXII e testo via Minemeld, secondo le logiche e le regole che saranno poi definite.

La guida ufficiale all'installazione di OpenTAXII è consultabile [qui](http://www.opentaxii.org/en/stable/installation.html) e [qui](http://www.opentaxii.org/en/stable/configuration.html).

Di seguito tutti gli step di installazione contestualizzati allo scenario in via di sperimentazione.
```
###############################################################
# tutti i comandi eseguiti si intendo eseguiti come utente root

apt install libxml2 libxml2-dev python-pip python-dev libxslt1-dev zlib1g-dev
pip install opentaxii

# altri pip packages necessari
pip install click jinja2 werkzeug itsdangerous python-dateutil lxml mysqlclient
```
Verificare la versione OpenTAXII installata; la versione 0.1.10 è quella testata e funzionante
```
pip list | grep ^openta
```
Di default OpenTAXII utilizza SQLite come backend. Nel nostro scenario usiamo mysql; durante l'installazione andremo ad impostare user e passwrd per l'utenza _root_
```
apt install mysql-server libmysqlclient-dev
```
Connettendosi con l'utenza _root_ 
```
mysql -u root -p
```
si va a creare l'utenza di servizio _taxii_ a cui si assegnano i permessi sui db di servizio _taxiiauth_ e _taxiipersist_
```
create database taxiiauth;
create database taxiipersist;
grant all on taxiiauth.* to 'taxii'@'%' identified by '<MYSQL_TAXII_PWD>';
grant all on taxiipersist.* to 'taxii'@'%' identified by '<MYSQL_TAXII_PWD>';
quit
```
Il server OpenTAXII è pronto per essere configurato.
