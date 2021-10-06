// const STUDY_DOMAIN = "resolver-downgrade-attack.dedyn.io";
const TEST_DOMAINS = [
  // Downgrade Test Domains
  "mitm-ra-ds8-ds13.ds13-ds16-dnskey13-dnskey16.downgrade.dedyn.io",
  "mitm-ra-ds8-ds13.ds8-ds15-dnskey15.downgrade.dedyn.io",
  "mitm-ra-ds8-ds13-ds15.ds13-ds16-dnskey13-dnskey16.downgrade.dedyn.io",
  "mitm-ra-ds8-ds13-ds15.ds16.downgrade.dedyn.io",
  "mitm-ra-ds8-ds13-ds15.ds8-ds15-dnskey15.downgrade.dedyn.io",
  "mitm-ra-ds8-ds13-ds15-ds16.ds8-ds16-dnskey16.downgrade.dedyn.io",
  "mitm-ra-ds8-ds13-ds15-ds16.ds16.downgrade.dedyn.io",
  "mitm-ra-ds8-ds13-ds15-ds16.ds8-ds15-dnskey15.downgrade.dedyn.io",
  "mitm-rs13-ra.ds8-ds16-dnskey16.downgrade.dedyn.io",
  "mitm-rs13-ra.ds8-ds13-dnskey8.downgrade.dedyn.io",
  "mitm-rs13-ra.ds8-ds15-dnskey8-dnskey15.downgrade.dedyn.io",
  "mitm-rs13-ra.ds13-ds16-dnskey13-dnskey16.downgrade.dedyn.io",
  "mitm-rs13-ra.ds16.downgrade.dedyn.io",
  "mitm-rs15-ra.ds8-ds16-dnskey16.downgrade.dedyn.io",
  "mitm-rs15-ra.ds8-ds13-dnskey13.downgrade.dedyn.io",
  "mitm-rs15-ra.ds8-dnskey8.downgrade.dedyn.io",
  "mitm-rs15-ra.ds8-ds16-dnskey8-dnskey16.downgrade.dedyn.io",
  "mitm-rs15-ra.ds13-ds16-dnskey13-dnskey16.downgrade.dedyn.io",
  "mitm-rs15-ra.ds16.downgrade.dedyn.io",
  "mitm-rs15-ra.ds8-ds16-dnskey16.downgrade.dedyn.io",
  "mitm-rs15-ra.ds8-ds15-dnskey15.downgrade.dedyn.io",
  "mitm-rs16-ra.ds8-ds13-dnskey13.downgrade.dedyn.io",
  "mitm-rs16-ra.ds15-ds16-dnskey15.downgrade.dedyn.io",
  "mitm-rs16-ra.ds13-ds16-dnskey16.downgrade.dedyn.io",
  "mitm-rs16-ra.ds13-ds16-dnskey13-dnskey16.downgrade.dedyn.io",
  "mitm-rs16-ra.ds8-ds13-dnskey8.downgrade.dedyn.io",
  "mitm-rs16-ra.ds8-ds15-dnskey8-dnskey15.downgrade.dedyn.io",
  "mitm-rs16-ra.ds13-dnskey13.downgrade.dedyn.io",
  "mitm-rs16-ra.ds8-ds13-dnskey8-dnskey13.downgrade.dedyn.io",
  "mitm-rs16-ra.ds13-ds15-dnskey15.downgrade.dedyn.io",
  "mitm-rs8-ra.ds8-ds16-dnskey16.downgrade.dedyn.io",
  "mitm-rs8-ra.ds15-ds16-dnskey16.downgrade.dedyn.io",
  "mitm-rs8-ra.ds13-ds16-dnskey16.downgrade.dedyn.io",
  "mitm-rs8-ra.ds13-ds16-dnskey13-dnskey16.downgrade.dedyn.io",
  "mitm-rs8-ra.ds13-dnskey13.downgrade.dedyn.io",
  "mitm-rs8-ra.ds13-ds15-dnskey13-dnskey15.downgrade.dedyn.io",
  "mitm-rs8-ra.ds8-ds13-dnskey8-dnskey13.downgrade.dedyn.io",
  "mitm-rs8-ra.ds8-dnskey8.downgrade.dedyn.io",
  "mitm-rs8-ra.ds16.downgrade.dedyn.io",
  "mitm-rs8-ra.ds8-ds16-dnskey8-dnskey16.downgrade.dedyn.io",

  // Algorithm Support Test Domains
  // "mitm.ds5-dnskey5.downgrade.dedyn.io",
  "mitm-ra.ds5-dnskey5.downgrade.dedyn.io",
  // "mitm.ds8-dnskey8.downgrade.dedyn.io",
  "mitm-ra.ds8-dnskey8.downgrade.dedyn.io",
  // "mitm.ds10-dnskey10.downgrade.dedyn.io",
  "mitm-ra.ds10-dnskey10.downgrade.dedyn.io",
  // "mitm.ds13-dnskey13.downgrade.dedyn.io",
  "mitm-ra.ds13-dnskey13.downgrade.dedyn.io",
  // "mitm.ds14-dnskey14.downgrade.dedyn.io",
  "mitm-ra.ds14-dnskey14.downgrade.dedyn.io",
  // "mitm.ds15-dnskey15.downgrade.dedyn.io",
  "mitm-ra.ds15-dnskey15.downgrade.dedyn.io",
  // "mitm.ds16-dnskey16.downgrade.dedyn.io",
  "mitm-ra.ds16-dnskey16.downgrade.dedyn.io",

  // Legacy Downgrade Test Domains
  "ecdsap256sha256.resolver-downgrade-attack.dedyn.io",
  "onlyrsasha256.resolver-downgrade-attack.dedyn.io",
  "rsasha256.resolver-downgrade-attack.dedyn.io",

  // Housekeeping Domains
  "broken.resolver-downgrade-attack.dedyn.io",
  // "resolver-downgrade-attack.dedyn.io",
];

const SESSION_FINISH_CANARY_DOMAIN = "resolver-downgrade-attack.dedyn.io";

const hash = parseInt(Math.random() * 0xFFFFFFFF);

function log(t)
{
    console.log(t);
}

var finished = 0;

function check_finished(){
  if (finished == TEST_DOMAINS.length){  // caveat: unbound recursion if '>=' instead of '=='
    query_domain(SESSION_FINISH_CANARY_DOMAIN);
  }
}

function query_domain(test_domain){

    log("Running: \"" + test_domain +"\"");
    
    var tester     = new Image();
    tester.onload  = function() {
        log("SUCCESS: \"" + test_domain +"\"");
        finished += 1;
        check_finished();
    };
    
    tester.onerror = function() {
        log("failure: \"" + test_domain +"\"");
        finished += 1;
        check_finished();
    };

    time = new Date().getTime();
    test_name = test_domain.split(".").slice(0, -3).join(".");
    if (test_name == ""){
      test_name = "session-finish";
    }
    src = "https://" + test_domain + "/img.png?test=" + test_name + "&tok=" + hash + "&time=" + time;
    log(src);
    tester.src = src;
}


for (var i = 0; i < TEST_DOMAINS.length; i++)
{
    query_domain(TEST_DOMAINS[i]);
}
