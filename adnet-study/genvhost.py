STUDY_DOMAIN = "resolver-downgrade-attack.dedyn.io"
TEST_DOMAINS = [
  "ecdsap256sha256",
  "onlyrsasha256",
  "rsasha256",
  "broken",
]

"""
This script assumes files/directories named according to acme.sh policy when using ZeroSSL CA.
"""


DOCROOT = "/var/www/resolver-downgrade-attack.dedyn.io"
LOGFILE_COMBINED = "access-downg.log"
LOGFILE_JSON = "access-downg.json"
LOG_FORMAT_JSON = "downg"
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
    # if testdomain != "":
    #     conflines.append(
    #         f"""ServerAlias *.{name}
    #         """
    #     )
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
