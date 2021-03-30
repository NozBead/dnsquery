# dnsquery

Programme pour réaliser une requête DNS de classe IN et de type A pour le nom de domaine en paramètre

## Compilation

	make dnsquery

## Usage

Pour obtenir l'adresse IPv4 derrière le nom de domaine *www.funetdelire.fr* en intérrogant le serveur 192.168.1.1 :

	./dnsquery www.funetdelire.fr 192.168.1.1
