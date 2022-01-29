#!/bin/sh

RED="\033[1;31m"
GREEN="\033[1;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
WHITE="\033[1;37m"
NOCOLOR="\033[0m"

AUTO=1
MODE=""
VERSION_IPAM="https://github.com/phpipam/phpipam/releases/download/v1.4.5/phpipam-v1.4.5.tgz"
NOM_IPAM="phpipam-v1.4.5.tgz"

## Variable pour la connexion a la bdd ##
BDD_LOCALHOST="localhost"
BDD_PHPIPAM="root"
BDD_PHPIPAMADMIN="$BDD_ROOT_MDP"
BDD_PHPIPAM2="phpipam"
BDD_DEFINE="/phpipam/" #http://NomDeDomaine/ = bdd_define="/" | http://NomDeDomaine/phpipam/ = bdd_define="/phpipam/"
BDD_ROOT_MDP="root"

## function pour les config apache et ipam ##
configapache () {
/sbin/a2enmod rewrite
mv /etc/apache2/sites-enabled/000-default.conf /etc/apache2/sites-enabled/000-default_new.conf
echo "	<VirtualHost *:80>
			DocumentRoot /var/www/phpipam
			<Directory "/var/www/phpipam">
				Options FollowSymLinks
				AllowOverride all
				Order allow,deny
				Allow from all
			</Directory>
			ErrorLog ${APACHE_LOG_DIR}/error.log
			CustomLog ${APACHE_LOG_DIR}/access.log combined
		</VirtualHost>" > /etc/apache2/sites-enabled/000-default.conf


}

configipam () {
echo "<?php

/**
 * database connection details
 ******************************/
$db['host'] = '$1';
$db['user'] = '$2';
$db['pass'] = '$3';
$db['name'] = '$4';
$db['port'] = 3306;

/**
 * Database webhost settings
 *
 * Change this setting if your MySQL database does not run on localhost
 * and you want to use the automatic database installation method to
 * create a database user for you (which by default is created @localhost)
 *
 * Set to the hostname or IP address of the webserver, or % to allow all
 ******************************/
//$db['webhost'] = '';


/**
 *  SSL options for MySQL
 *
 See http://php.net/manual/en/ref.pdo-mysql.php
     https://dev.mysql.com/doc/refman/5.7/en/ssl-options.html
     Please update these settings before setting 'ssl' to true.
     All settings can be commented out or set to NULL if not needed
     php 5.3.7 required
 ******************************/
$db['ssl']        = false;                           // true/false, enable or disable SSL as a whole
$db['ssl_key']    = '/path/to/cert.key';             // path to an SSL key file. Only makes sense combined with ssl_cert
$db['ssl_cert']   = '/path/to/cert.crt';             // path to an SSL certificate file. Only makes sense combined with ssl_key
$db['ssl_ca']     = '/path/to/ca.crt';               // path to a file containing SSL CA certs
$db['ssl_capath'] = '/path/to/ca_certs';             // path to a directory containing CA certs
$db['ssl_cipher'] = 'DHE-RSA-AES256-SHA:AES128-SHA'; // one or more SSL Ciphers
$db['ssl_verify'] = 'true';                          // Verify Common Name (CN) of server certificate?
$db['tmptable_engine_type'] = "MEMORY";              // Temporary table type to construct complex queries (MEMORY, InnoDB)
$db['use_cte']    = 1;                               // Use recursive CTE queries [>=MariaDB 10.2.2, >=MySQL 8.0] (0=disabled, 1=autodetect, 2=force enable)


/**
 * Mail sending and other parameters for pingCheck and DiscoveryCheck scripts
 ******************************/

# pingCheck.php script parameters
$config['ping_check_send_mail']        = true;       // true/false, send or not mail on ping check
$config['ping_check_method']           = false;      // false/ping/pear/fping, reset scan method
# discoveryCheck.php script parameters
$config['discovery_check_send_mail']   = true;       // true/false, send or not mail on discovery check
$config['discovery_check_method']      = false;      // false/ping/pear/fping, reset scan method
# remove_offline_addresses.php script parameters
$config['removed_addresses_send_mail'] = true;       // true/false, send or not mail on pomoving inactive addresses
$config['removed_addresses_timelimit'] = 86400 * 7;  // int, after how many seconds of inactivity address will be deleted (7 days)
# resolveIPaddresses.php script parameters
$config['resolve_emptyonly']           = true;       // if true it will only update the ones without DNS entry!
$config['resolve_verbose']             = true;       // verbose response - prints results, cron will email it to you!
$config['disable_main_login_form']     = false;      // disable main login form if you want use another authentification method by default (SAML, LDAP, etc.)


/**
 * php debugging on/off
 *
 * true  = SHOW all php errors
 * false = HIDE all php errors
 ******************************/
$debugging = false;

/*
 * API Crypt security provider. "mcrypt" or "openssl*"
 * Supported methods:
 *    openssl-128-cbc (alias openssl, openssl-128) *default
 *    openssl-256-cbc (alias openssl-256)
 *
 * default as of 1.3.2 "openssl-128-cbc"
 ******************************/
// $api_crypt_encryption_library = "mcrypt";


/**
 * Allow API calls over HTTP (security = none)
 *
 * @var bool
 */
$api_allow_unsafe = false;

/**
 *  manual set session name for auth
 *  increases security
 *  optional
 ******************************/
$phpsessname = "phpipam";

/**
 * Cookie SameSite settings ("None", "Lax"=Default, "Strict")
 * - "Strict" increases security
 * - "Lax" required for SAML2, some SAML topologies may require "None".
 * - "None" requires HTTPS (implies "Secure;")
 */
$cookie_samesite = "Lax";

/**
 * Session storage - files or database
 *
 * @var string
 */
$session_storage = "files";


/**
 * Path to access phpipam in site URL, http:/url/BASE/
 *
 * BASE definition should end with a trailing slash "/"
 * BASE will be set automatically if not defined. Examples...
 *
 *  If you access the login page at http://phpipam.local/           =  define('BASE', "/");
 *  If you access the login page at http://company.website/phpipam/ =  define('BASE', "/phpipam/");
 *  If you access the login page at http://company.website/ipam/    =  define('BASE', "/ipam/");
 *
 ******************************/
if(!defined('BASE'))
define('BASE', "$5");


/**
 * Multicast unique mac requirement - section or vlan
 ******************************/
if(!defined('MCUNIQUE'))
define('MCUNIQUE', "section");

/**
 * Permit private subpages - private apps under /app/tools/custom/<custom_app_name>/index.php
 ******************************/
$private_subpages = array();

/**
 * proxy connection details
 ******************************/
$proxy_enabled  = false;                                  // Enable/Disable usage of the Proxy server
$proxy_server   = 'myproxy.something.com';                // Proxy server FQDN or IP
$proxy_port     = '8080';                                 // Proxy server port
$proxy_user     = 'USERNAME';                             // Proxy Username
$proxy_pass     = 'PASSWORD';                             // Proxy Password
$proxy_use_auth = false;                                  // Enable/Disable Proxy authentication

$offline_mode   = false;                                  // Offline mode, disable server-side Internet requests (proxy/OpenStreetMap)

/**
 * Failed access
 * Message to log into webserver logs in case of failed access, for further processing by tools like Fail2Ban
 * The message can contain a %u parameter which will be replaced with the login user identifier.
 ******************************/
// $failed_access_message = '';

/**
 * General tweaks
 ******************************/
$config['logo_width']             = 220;                    // logo width
$config['requests_public']        = true;                   // Show IP request module on login page
$config['split_ip_custom_fields'] = false;                  // Show custom fields in separate table when editing IP address
$config['footer_message']         = "";                     // Custom message included in the footer of every page

/**
 * PHP CLI binary for scanning and network discovery.
 *
 * The default behaviour is to use the system wide default php version symlinked to php in PHP_BINDIR (/usr/bin/php).
 * If multiple php versions are present; overide selection with $php_cli_binary.
 */
// $php_cli_binary = '/usr/bin/php7.1';

/**
 * Path to mysqldump binary
 *
 * default: '/usr/bin/mysqldump'
 */
// $mysqldump_cli_binary = '/usr/bin/mysqldump';" > config.php
}

#### Choix ####
echo -n "${YELLOW}0# | ${GREEN}Mode AUTO ou MANUELLE (auto):\n"
read CHOIX

case $CHOIX in

manuelle | m)
	echo "${GREEN}Mode MANUELLE :${NOCOLOR}\n"
	AUTO=0
	MODE="MANUELLE"
	;;

*)
echo "${GREEN}Mode AUTO :${NOCOLOR}\n"
	AUTO=1
	MODE="AUTO"
	;;
esac
#### FIN ####


echo "${BLUE}1# | Début de l'installation de phpIPAM en mode ${MODE}\n"

#### Mise à jour dépots ####
if test $AUTO = 0
then
	echo -n "${YELLOW}1# | ${GREEN}Voulez-vous mettre à jour vos dépots ? (O/n)${NOCOLOR}\n"
	read a
	case $a in
	non | n)
		echo "${RED}Annulations des mise à jour des dépôts ...${NOCOLOR}\n"
		;;
	*)
		echo "${GREEN}Mise à jour des dépots:${NOCOLOR}\n"
		apt update
		echo "\n"
		;;
	esac

elif  test $AUTO = 1
then
	echo "${YELLOW}1# | ${GREEN}Mise à jour des dépots:${NOCOLOR}\n"
	apt update
	echo "\n"
fi
#### FIN ####



#### Installations des paquets ####
if test $AUTO = 0
then
	echo -n "${YELLOW}02# | ${GREEN}Voulez-vous installez les paquets ? (O/n)${NOCOLOR}\n"
	read b
	case $b in
		non | n)
		echo "${RED}Annulations des mise à jour des dépôts ...${NOCOLOR}\n"
		;;
	*)
		echo "${GREEN}Installations des paquets:${NOCOLOR}\n"
		apt -y upgrade
		echo "\n"
		;;
	esac

elif test $AUTO = 1
then
	echo "${YELLOW}2# | ${GREEN}Mise à jour des dépots:${NOCOLOR}\n"
	apt -y upgrade
	echo "\n"
fi
#### FIN ####



#### Installations pour DEBIAN ou CENTOS ####

echo -n "${YELLOW}3# | ${GREEN}Voulez-vous installez IPAM pour Debian ou CentOS ?${NOCOLOR}\n"
read c
case $c in
debian | d)
	echo "${GREEN}Installation pour Debian :${NOCOLOR}\n"
	OS="DEBIAN"
	;;
centos | c)
	echo "${GREEN}Installation CentOS :${NOCOLOR}\n"
	OS="CENTOS"
	;;
*)
	echo "${RED} Erreur de saisie ! (d = Debian || c = CentOS)${NOCOLOR}"
	exit
	;;
	esac

#### FIN ####



######## Installation pour Debian ########

if test $OS = "DEBIAN"
then

#### Installations des paquets : Apache, PHP et MySQL ####

if test $AUTO = 0
then
	echo -n "${YELLOW}4# | ${GREEN}Voulez-vous installez les paquets pour Apache, PHP et MySQL? (O/n${NOCOLOR})\n"
	read d
	case $d in
	non | n)
		echo "${RED}Annulations ...${NOCOLOR}\n"
		;;
	*)
		echo "${GREEN}Installations des paquets :${NOCOLOR}\n"
		apt-get install -y fping php-snmp apache2 mariadb-server php php-pear php-gmp php-mysql php-mbstring php-gd php-curl php-cli git
		;;
	esac

elif test $AUTO = 1
then
	echo "${YELLOW}4# | ${GREEN}Installations des paquets pour l'installation d'Apache, PHP et MySQL :${NOCOLOR}\n"
	apt-get install -y fping php-snmp apache2 mariadb-server php php-pear php-gmp php-mysql php-mbstring php-gd php-curl php-cli git
fi

#### FIN ####



######## Téléchargement de IPAM depuis la source ########

if test $AUTO = 0
then
	echo -n "${YELLOW}5# | ${GREEN}Voulez-vous télécharger IPAM depuis la source ${VERSION_IPAM} ? (O/n)${NOCOLOR}\n"
	read e
	case $e in
	non | n)
		echo "${RED}Annulations du téléchargement d'IPAM ...${NOCOLOR}\n"
		echo -n "${GREEN}Voulez-vous arrêter l'assistant d'installation(O/n)${NOCOLOR}\n"
		read eb
		case $eb in
			non | n)
				echo "..."
				;;
			*)
				echo "${RED}Annulations ...${NOCOLOR}\n"
				exit
				;;
			esac
	;;
	*)
		echo "${GREEN}Téléchargemant d'IPAM :${NOCOLOR}\n"
		cd /var/www/
		wget ${VERSION_IPAM}
		echo "${GREEN}Décompression de l'archive :${NOCOLOR}\n"
		tar -zxvf ${NOM_IPAM}
		echo -n "${GREEN}Voulez-vous supprimer l'archive télécharger(O/n)${NOCOLOR}\n"
		read ea
		case $ea in
			non | n)
				echo "..."
				;;
			*)
				echo "${RED}Suppression ...${NOCOLOR}\n"
				rm ${NOM_IPAM}
				;;
		esac		
	;;
	esac

elif test $AUTO = 1
then
	echo "${YELLOW}5# | ${GREEN} Téléchargement d'IPAM depuis la source :${NOCOLOR}\n"
	cd /var/www/
	wget ${VERSION_IPAM}
	tar -zxvf ${NOM_IPAM}
fi

#### FIN ####

echo "${BLUE}6# | Configuration d'Apache, MySQL et phpIpam ${NOCOLOR}\n"

#### Configuration d'Apache ####

if test $AUTO = 0
then
	echo -n "${YELLOW}6# | ${GREEN}Voulez-vous configurer Apache ? (O/n${NOCOLOR})\n"
	read f
	case $f in
	non | n)
		echo "${RED}Annulations ...${NOCOLOR}\n"
		;;
	*)
		echo "${GREEN}Configuration ...${NOCOLOR}\n"
		configapache
		systemctl restart apache2 
		;;
	esac

elif test $AUTO = 1
then
	echo "${YELLOW}6# | ${GREEN}Configuration d'Apache :${NOCOLOR}\n"
	configapache
	systemctl restart apache2 
fi

#### FIN ####

#### Configuration de MySQL ####

if test $AUTO = 0
then
	echo -n "${YELLOW}7# | ${GREEN}Voulez-vous configurer MySQL ? (O/n${NOCOLOR})\n"
	read f
	case $f in
	non | n)
		echo "${RED}Annulations ...${NOCOLOR}\n"
		;;
	*)
		echo "${GREEN}Configuration ...${NOCOLOR}\n"
		mysql_secure_installation
		;;
	esac

elif test $AUTO = 1
then
	echo "${YELLOW}7# | ${GREEN}Configuration de MySQL :${NOCOLOR}\n"
	mysql_secure_installation
fi

#### FIN ####

#### Configuration à la connexion à la base de donnée ####
echo "${BLUE}2# | Configuration du fichier config.php pour la connexion à la base de donnée :${NOCOLOR}\n"
if test $AUTO = 0
then
	echo -n "${YELLOW}8# | ${GREEN}Voulez-vous configurer le fichier config.php (connexion bdd uniquement) (O/n)${NOCOLOR}\n"
	read g
	case $g in
	non | n)
		echo "${RED}Annulations de la configuration ...${NOCOLOR}\n"
		;;
	*)
		echo "${GREEN}Configuration du fichier :${NOCOLOR}\n"
		cd /var/www/phpipam
		echo -n "${YELLOW}9# | ${GREEN}L'url de connexion à la base de donnée :${NOCOLOR}\n"
		read localhost
		BDD_LOCALHOST=$localhost
		
		echo -n "${YELLOW}10# | ${GREEN}User de la base de donnée :${NOCOLOR}\n"
		read phpipam
		BDD_PHPIPAM=$phpipam
		
		echo -n "${YELLOW}11# | ${GREEN}Mot de passe de l'utilisateur de la base de donnée :${NOCOLOR}\n"
		read phpipamadmin
		BDD_PHPIPAMADMIN=$phpipamadmin
		
		echo -n "${YELLOW}12# | ${GREEN}Nom de la base de donnée :${NOCOLOR}\n"
		read phpipam2
		BDD_PHPIPAM2=$phpipam2
		
		echo -n "${YELLOW}13# | ${GREEN}Base de l'url : \nExemple: http://NomDeDomaine/ = bdd_define='/' | http://NomDeDomaine/phpipam/ = bdd_define='/phpipam/'${NOCOLOR}\n"
		read define
		BDD_DEFINE=$define
		
		configipam BDD_LOCALHOST BDD_PHPIPAM BDD_PHPIPAMADMIN BDD_PHPIPAM2 BDD_DEFINE
		;;
	esac

elif test $AUTO = 1
then
	echo "${YELLOW}14# | ${GREEN}Configuration du fichier config.php pour la connexion à la base de donnée :${NOCOLOR}\n"
	configipam BDD_LOCALHOST BDD_PHPIPAM BDD_PHPIPAMADMIN BDD_PHPIPAM2 BDD_DEFINE
	
fi

#### FIN ####



#### Configuration de la base de donnée ####
echo "${GREEN}Création de la base de donnée phpIpam:${NOCOLOR}\n"
if test ${AUTO} = 0
then
	echo -n "${YELLOW}15# | ${GREEN}Voulez-vous créer la base de donnée ? (O/n)${NOCOLOR}\n"
	read h
	case $h in
	non | n)
		echo "${RED}Annulations de la création ...${NOCOLOR}\n"
		;;
	*)
		echo "${GREEN}Création de la base :${NOCOLOR}\n"
		mysql -u root -p --excute="
			CREATE USER "${BDD_PHPIPAM}"@'localhost' IDENTIFIED BY "${BDD_PHPIPAMADMIN}";
			GRANT ALL PRIVILEGES ON *.* TO "${BDD_PHPIPAM}"@'localhost' with grant option;
			FLUSH PRIVILEGES;"

		;;
	esac

elif test ${AUTO} = 1
then
	echo "${GREEN}Configuration du mot de passe Root dans MySql :${NOCOLOR}\n"
	mysql -u root -p --excute="
			CREATE USER "${BDD_PHPIPAM}"@'localhost' IDENTIFIED BY "${BDD_PHPIPAMADMIN}";
			GRANT ALL PRIVILEGES ON *.* TO "${BDD_PHPIPAM}"@'localhost' with grant option;
			FLUSH PRIVILEGES;"
		
	fi

#### FIN ####



#### Configuration des permissions ####

if test $AUTO = 0
then
	echo -n "${YELLOW}16# | ${GREEN}Voulez-vous configurer les permissions ? (O/n${NOCOLOR})\n"
	read f
	case $f in
	non | n)
		echo "${RED}Annulations ...${NOCOLOR}\n"
		;;
	*)
		echo "${GREEN}Configuration ...${NOCOLOR}\n"
		chown www-data:www-data -R /var/www/phpipam/
		cd /var/www/phpipam/
		find . -type f -exec chmod 0644 {} \;
		find . -type d -exec chmod 0755 {} \;
		;;
	esac

elif test $AUTO = 1
then
	echo "${YELLOW}16# | ${GREEN}Configuration des permissions :${NOCOLOR}\n"
	chown www-data:www-data -R /var/www/phpipam/
	cd /var/www/phpipam/
	find . -type f -exec chmod 0644 {} \;
	find . -type d -exec chmod 0755 {} \;
fi

#### FIN ####



#### Configuration des taches CRON ####

if test $AUTO = 0
then
	echo -n "${YELLOW}17# | ${GREEN}Voulez-vous configurer les tâches CRON ? (O/n${NOCOLOR})\n"
	read f
	case $f in
	non | n)
		echo "${RED}Annulations ...${NOCOLOR}\n"
		;;
	*)
		echo "${GREEN}Configuration ...${NOCOLOR}\n"
		echo "# update host statuses every 5 minutes
			*/5 * * * * www-data /usr/bin/php /var/www/phpipam/functions/scripts/pingCheck.php >> /dev/null 2>&1
			*/5 * * * * www-data /usr/bin/php /var/www/phpipam/functions/scripts/discoveryCheck.php >> /dev/null 2>&1" | tee /etc/cron.d/phpipam
			ip=hostname -I
		echo "${GREEN}Voici les informations sur la base donnée à renseigner sur le site (${hostname}/phpipam/)\n - Adresse de la BDD : ${BDD_LOCALHOST}\n - Nom d'Utilisateur : ${BDD_PHPIPAM}\n - Mot de passe Utilisateur : ${BDD_PHPIPAMADMIN}\n - Nom de la BDD : ${BDD_PHPIPAM2}\n - Mode de Passe Root BDD : ${BDD_ROOT_MDP}${NOCOLOR}\n"

		;;
	esac

elif test $AUTO = 1
then
	echo "${YELLOW}17# | ${GREEN}Configuration des tâches CRON :${NOCOLOR}\n"
	echo "# update host statuses every 5 minutes
		*/5 * * * * www-data /usr/bin/php /var/www/phpipam/functions/scripts/pingCheck.php >> /dev/null 2>&1
		*/5 * * * * www-data /usr/bin/php /var/www/phpipam/functions/scripts/discoveryCheck.php >> /dev/null 2>&1" | sudo tee /etc/cron.d/phpipam
	ip=hostname -I
	echo "${GREEN}Voici les informations sur la base donnée à renseigner sur le site (${hostname}/phpipam/)\n - Adresse de la BDD : ${BDD_LOCALHOST}\n - Nom d'Utilisateur : ${BDD_PHPIPAM}\n - Mot de passe Utilisateur : ${BDD_PHPIPAMADMIN}\n - Nom de la BDD : ${BDD_PHPIPAM2}\n - Mode de Passe Root BDD : ${BDD_ROOT_MDP}${NOCOLOR}\n"

fi

#### FIN ####
fi


#### Installation pour CentOS ####

#### FIN ####


echo "${WHITE}" #Définit la couleut de l'écriture en blanc
