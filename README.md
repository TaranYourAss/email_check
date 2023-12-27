# email_check
Queries MXToolBox and checks DKIM, DMARC, and SPF records for a given domain.  
Automatically finds all selectors for a domain, unless specified which selectors to check.

## Installation
This repo can be installed by downloading the zip file [here](https://github.com/TaranYourAss/email_check/archive/master.zip) or by cloning the repository:  

`git clone https://github.com/TaranYourAss/email_check.git`  


### Dependencies
This script relies on the curl_cffi library: [https://github.com/yifeikong/curl_cffi](https://github.com/yifeikong/curl_cffi)  

You can install all depenencies via:  
`pip install -r requirements.txt`

  
## Usage
Example:  
This will run all checks against the Twitch domain with only the "google" DKIM selector being checked for DKIM failures, and then print verbose details.  
`python3 email_check.py -v -d twitch.tv -s google`  

If you do not know what selectors a domain uses, you can just input the domain and the script will automatically find all selectors for that domain.  
`python3 email_check.py -d twitch.tv`

> [\*] Running DMARC, DKIM, and SPF checks for twitch.tv...  
> [*] Found 7 DKIM selectors for twitch.tv:  
>&nbsp;-&nbsp;&nbsp;google&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-&nbsp;&nbsp;zendesk2  
>&nbsp;-&nbsp;&nbsp;s1&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-&nbsp;&nbsp;mandrill  
>&nbsp;-&nbsp;&nbsp;s2&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-&nbsp;&nbsp;k1  
>&nbsp;-&nbsp;&nbsp;zendesk1  
> [\*] DKIM Check: PASS  
> [\*] SPF Check: FAIL  
> [\*] DMARC Check: PASS

Using the `-v` flag can show you exactly why a check failed:  
> [\*] SPF Check: FAIL  
>&nbsp;&nbsp;&nbsp;&nbsp;Record Content: v=spf1 include:_spf.google.com include:amazonses.com include:spf.mtasv.net include:mail.zendesk.com include:_spf.twitch.tv include:aspmx.pardot.com a mx -all  
>&nbsp;&nbsp;&nbsp;&nbsp;Failed:  
>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;* SPF Included Lookups - Too many included lookups (12)  
>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; -&nbsp;&nbsp;https://mxtoolbox.com/Problem/spf/SPF-Included-Lookups?page=prob_spf&showlogin=1&hidetoc=1&action=spf:twitch.tv  

