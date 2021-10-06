# STUDY_DOMAIN = "resolver-downgrade-attack.dedyn.io"
# TEST_DOMAINS = [
#   "ecdsap256sha256",
#   "onlyrsasha256",
#   "rsasha256",
#   "broken",
# ]


STUDY_DOMAIN = "downgrade.dedyn.io"
TEST_DOMAINS = [
  "ds13-dnskey13",
  "ds13-ds15-dnskey13-dnskey15",
  "ds13-ds15-dnskey15",
  "ds13-ds16-dnskey13-dnskey16",
  "ds13-ds16-dnskey16",
  "ds15-ds16-dnskey15",
  "ds16",
  "ds8-dnskey8",
  "ds8-ds13-dnskey13",
  "ds8-ds13-dnskey8",
  "ds8-ds13-dnskey8-dnskey13",
  "ds8-ds15-dnskey15",
  "ds8-ds15-dnskey8-dnskey15",
  "ds8-ds16-dnskey16",
  "ds8-ds16-dnskey8-dnskey16",

  "ds5-dnskey5",
  "ds8-dnskey8",
  "ds10-dnskey10",
  "ds13-dnskey13",
  "ds14-dnskey14",
  "ds15-dnskey15",
  "ds16-dnskey16",
]


"""
This script assumes files/directories named according to acme.sh policy when using ZeroSSL CA.
"""


# DOCROOT = "/var/www/resolver-downgrade-attack.dedyn.io"
DOCROOT = "/var/www/downgrade.dedyn.io"
LOGFILE_COMBINED = "access-downg.log"
LOGFILE_JSON = "access-downg.json"
LOG_FORMAT_JSON = "downg2"
APACHE_LOG_DIR = "{APACHE_LOG_DIR}"  # hacky but does the job

def gen_vhost_config(testdomain="", study_domain=STUDY_DOMAIN):
    conflines = []
    if testdomain == "":
        name = study_domain
    else:
        name = testdomain + "." + study_domain
    conflines.append(
        f"""
        <VirtualHost *:443>
            ServerName {name}
        """
        )
    if testdomain != "":
        conflines.append(
            f"""    ServerAlias *.{name}
            """
        )
    conflines.append(
        f"""
            ServerAdmin webmaster@localhost
            DocumentRoot {DOCROOT}
            ErrorLog ${APACHE_LOG_DIR}/error.log
            CustomLog ${APACHE_LOG_DIR}/{LOGFILE_COMBINED} combined
            CustomLog ${APACHE_LOG_DIR}/{LOGFILE_JSON} {LOG_FORMAT_JSON}
        """
    )
    conflines.append(
        f"""
            SSLEngine On
            SSLCertificateFile    /etc/apache2/ssl/{name}/fullchain.cer
            SSLCertificateKeyFile /etc/apache2/ssl/{name}/{name}.key
            SSLCACertificateFile  /etc/apache2/ssl/{name}/ca.cer

            ProxyPass        "/post/" "http://127.0.0.1:5000/post/"
            ProxyPassReverse "/post/" "http://127.0.0.1:5000/post/"

        </VirtualHost>
        """
        )
    return "".join(conflines)
    


def gen_hosts():
    config = []
    config += gen_vhost_config(testdomain="", study_domain=STUDY_DOMAIN)
    for test_domain in TEST_DOMAINS:
        config += gen_vhost_config(testdomain=test_domain, study_domain=STUDY_DOMAIN)
    return "".join(config)


if __name__ == "__main__":
    with open("vhosts.conf-part", 'w') as f:
        f.writelines([gen_hosts()])
