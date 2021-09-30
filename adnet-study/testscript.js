const STUDY_DOMAIN = "resolver-downgrade-attack.dedyn.io";
const TEST_DOMAINS = [
  "ecdsap256sha256",
  "onlyrsasha256",
  "rsasha256",
  "broken",
]
const SESSION_FINISH_CANARY_DOMAIN = ""


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
    if (test_domain == ""){
      src = "https://" + STUDY_DOMAIN + "/img.png?test=" + "finish" + "&tok=" + hash + "&time=" + time;
    } else {
      src = "https://" + test_domain + "." + STUDY_DOMAIN + "/img.png?test=" + test_domain + "&tok=" + hash + "&time=" + time;
    }
    log(src);
    tester.src = src;
}


for (var i = 0; i < TEST_DOMAINS.length; i++)
{
    query_domain(TEST_DOMAINS[i]);
}
