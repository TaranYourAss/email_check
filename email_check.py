import time
import re
import json
import argparse
from curl_cffi import requests

class dkim_check:
    def __init__(self, domain:str, selector:str|list=None):

        self.result = None #Set a default result of None so
        self.warnings = []
        self.failures = []

        
        #domain arg must be a string and cannot be empty
        
        if type(domain) is not str:
            raise Exception("Domain must be a string.")
        elif domain is None:
            raise Exception("Domain cannot be empty.")
        else:
            self.domain = domain

        
        #selector arg must be in one of the following formats:
        #1. a string if there is only one selector
        #2. a list of strings if there are multiple selectors

        #otherwise, leave the selector parameter blank and the script will find the selectors automatically
        
        
        #--FIND SELECTORS AUTOMATICALLY IF NONE PROVIDED--
        if selector == None:
            self.selectors = self.find_selectors() #no selector was specified, so find them    
            if self.selectors is None:
                raise Exception("Failed to find selectors from response.")
            elif self.selectors == []:
                self.result = "FAIL" #dkim check fails if there are no selectors for the domain
                self.failures.append(f"No DKIM selectors found for {self.domain}.")
                return #exit init if there are no selectors for the domain
        
        #--CHECK IF PROVIDED SELECTORS ARE VALID--
        
        #selector was specified, so check if it's a list or string
        elif not isinstance(selector, (str, list)):
            raise Exception(f"Selector must be a list or string. - {selector} - {type(selector)}")
        
        #selector was specified as a string, so convert it to a list of dictionaries for consistency
        elif type(selector) is str: 
            self.selectors = [{"name": selector}]
        
        #selector was specified as a list
        elif type(selector) is list: 
            if selector == []:
                raise Exception("Selector list cannot be empty.")
            else:
                for selector_ in selector:
                    if type(selector_) is not str: #list of selectors must only contain strings for consistency
                        raise Exception(f"Selector list must only contain strings. - {selector} - {type(selector_)}")
                    else:
                        #convert each selector to a dictionary for consistency
                        self.selectors = []
                        for selector_ in selector:
                            self.selectors.append({"name": selector_})
        else:
            raise Exception("Failed to parse selectors.") #idk what could cause this, but just in case
        
        """
        self.selectors must be a list of dictionaries at this point:
        [{"name": "selector1"}, {"name": "selector2"}]
        """
        #print(self.selectors)

        #DO DKIM CHECKS
        self.check_dkim()
    
    def find_selectors(self):
        """
        Queries EasyDMARC to automagically find the selectors of a domain.
        
        Returns a list of selectors if successful.
        Returns None if it fails.
        Returns an empty list if there are no selectors for the domain.
        """
        
        #--QUERY FOR ALL SELECTORS--
        easydmarc_url = f"https://easydmarc.com/tools/dkim-lookup/status?domain={self.domain}&amp;selector=auto"
        
        response = self.query(easydmarc_url)
        #print(response.text)

        #--PARSE EasyDMARC RESPONSE--
        #response from EasyDMARC will be in HTML format
        #each selector is in a div with the class "title"
        
        #Determine if there are no selectors for the domain
        #EasyDMARC will return a div with the class "mb-4 no-data-title" if there are no selectors
        no_selectors_for_domain = re.search(r'<div class="mb-4 no-data-title">no selectors detected</div>', response.text)
        if no_selectors_for_domain:
            return [] #cause DKIM check to fail if there are no selectors for the domain
        
        #if there are selectors, EasyDMARC will return a div with the class "title"
        #this regex will find all the selectors
        matches = re.findall(r'<div class="title " style="font-size: 18px;">(.*?)</div>', response.text)

        selectors = []
        if matches:
            for match in matches:
                selectors.append({"name": match})
            return selectors
        else:
            return None #failed to find selectors from response
        
    def check_dkim(self):
        """
        Collects DKIM data for each selector from MXToolbox.
        Checks each selector for failed MXtoolbox checks.

        MXToolbox data is stored in each selectors dictionary.

                    
        check_dkim() will fail if:
        1. any non-testing dkim selectors fail an MXToolbox check

        check_dkim() will produce warnings if:
        1. any dkim selectors have warnings from MXToolbox
        2. the domain is only using test DKIM selectors (Tag: t)

            
        
        """
        for selector in self.selectors:
            selector_domain_name = selector["name"] + '._domainkey.' + self.domain            
            #--QUERY MXTOOLBOX FOR DKIM--
            #mxtoolbox requires authentication to query their tools
            #they do provide a free API, but you'll need an API key
            #using this method is more user friendly as it automatically generates a temporary authentication key

            #this will query mxtoolbox for a temporary authentication key
            temp_auth_mxtoolbox_url = f"https://mxtoolbox.com/api/v1/user"
            temp_auth = self.query(temp_auth_mxtoolbox_url)
            temp_auth_json = temp_auth.json()
            #print(json.dumps(temp_auth_json, indent=4, sort_keys=True))
            temp_auth_key = temp_auth_json["TempAuthKey"]
            
            #this will run the MXToolbox DKIM check
            dkim_mxtoolbox_url = f"https://mxtoolbox.com/api/v1/lookup?command=dkim&argument={selector_domain_name}&resultIndex=1&disableRhsbl=true&format=0"
            mxtoolbox_headers = {
                "Tempauthorization": temp_auth_key,
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
            }
            response = self.query(dkim_mxtoolbox_url, headers=mxtoolbox_headers)
            mxtoolbox_selector_dkim_lookup_json = response.json()
            #print(json.dumps(response_json, indent=4, sort_keys=True))

            #--SAVE MXTOOLBOX DKIM DATA--
            selector["failed"] = mxtoolbox_selector_dkim_lookup_json["Failed"]
            selector["warnings"] = mxtoolbox_selector_dkim_lookup_json["Warnings"]
            selector["passed"] = mxtoolbox_selector_dkim_lookup_json["Passed"]
            selector["record-content"] = str(mxtoolbox_selector_dkim_lookup_json["Information"][0]["Description"])
            selector["information"] = mxtoolbox_selector_dkim_lookup_json["Information"]
            selector["errors"] = mxtoolbox_selector_dkim_lookup_json["Errors"]
            selector["timeouts"] = mxtoolbox_selector_dkim_lookup_json["Timeouts"]
            selector["is_testing_selector"] = False #default value is False
            
            #--CHECK IF DKIM RECORD IS A TEST RECORD--
            for information in selector["information"]:
                if information["Tag"] == "t": #t tag means it's a testing DKIM record
                    selector["is_testing_selector"] = True
                    break
            
            #--CHECK IF DKIM RECORD HAS ANY FAILED CHECKS--        
            if selector["failed"] == []:
                selector["valid"] = True
            else:
                selector["valid"] = False
        
        #--CHECK IF DKIM CHECK FAILED--
        #if any non-testing selector is not valid, then the DKIM check fails
        for selector in self.selectors:
            if selector["is_testing_selector"] == False and selector["valid"] == False:
                self.result = "FAIL"
                self.failures.append(f"Selector {selector['name']} failed MXToolbox checks.")
                return
            else:
                self.result = "PASS"
        #--Produce warnings if any testing selector has failed checks--
        for selector in self.selectors:
            if selector["is_testing_selector"] == True and selector["valid"] == False:
                self.warnings.append(f"Testing Selector {selector['name']} failed MXToolbox checks.")
            
        #--Produce warnings if any selector has warnings--
        mxtoolbox_warnings = []
        for selector in self.selectors:
            if selector["warnings"] != []:
                mxtoolbox_warnings.append(f"Selector {selector['name']} has warnings: {selector['warnings']}")
        self.warnings.append(mxtoolbox_warnings)

        #--Produce warnings if all selectors are testing selectors--
        total_selectors = len(self.selectors)
        testing_selectors = 0
        for selector in self.selectors:
            if selector["is_testing_selector"] == True:
                testing_selectors += 1
        if total_selectors == testing_selectors:
            self.warnings.append(f"All selectors are test selectors for {self.domain}. Please add a non-testing selector to your domain.")
        
    def query(self, endpoint:str, headers:str="", impersonate:str="chrome110"):
        """
        -runs a GET request against the provided endpoint and returns the raw requests.Session() GET response
        -slowly retries up to 5 times if the request fails
        -impersontates chrome110 by default - this gets around TLS fingerprinting, as
        mxtoolbox will block any traffic (returns 401) using the requests library TLS fingerprint. 
        
        """
        session = requests.Session()
        retries = 5
        num_of_trys = 0
        while num_of_trys < retries:
            try:
                response = session.get(endpoint, headers=headers, impersonate=impersonate)
                response.raise_for_status() #check if the status isn't successful
                return response
            
            except requests.exceptions.HTTPError as http_err:
                if response.status_code == 401: #no need to retry if the error is 401
                    raise Exception(f"Unauthorized access to {endpoint}. Please check your credentials. - {response.status_code} - {response.reason} - {response.text}")
                num_of_trys += 1
                time.sleep(1)
            except Exception as err: #generic and unknown errors that don't fall under HTTPError
                raise Exception(f"Failed to query {endpoint} with error: {err}")
        #this exception will only trigger if num_of_trys is less than retries - i.e it tried 5 times
        raise Exception(f"Failed to query {endpoint} after 5 retries. Last HTTP status code: {response.status_code} - {response.reason} - {response.text}")
            

class spf_check:
    def __init__(self, domain:str):
        self.result = None
        #domain arg must be a string and cannot be empty
        if type(domain) is not str:
            raise Exception("Domain must be a string.")
        elif domain is None:
            raise Exception("Domain cannot be empty.")
        else:
            self.domain = domain
        
        #DO SPF CHECKS
        self.check_spf()
        

    def check_spf(self):
            """
            Queries MXToolbox SPF Check .
            Checks for failed MXtoolbox checks.
            """
            
            #--QUERY MXTOOLBOX FOR SPF--
            #mxtoolbox requires authentication to query their tools
            #they do provide a free API, but you'll need an API key
            #using this method is more user friendly as it automatically generates a temporary authentication key

            #this will query mxtoolbox for a temporary authentication key
            temp_auth_mxtoolbox_url = f"https://mxtoolbox.com/api/v1/user"
            temp_auth = self.query(temp_auth_mxtoolbox_url)
            temp_auth_json = temp_auth.json()
            #print(json.dumps(temp_auth_json, indent=4, sort_keys=True))
            temp_auth_key = temp_auth_json["TempAuthKey"]
                
            #this will run the MXToolbox DKIM check
            spf_mxtoolbox_url = f"https://mxtoolbox.com/api/v1/lookup?command=spf&argument={self.domain}&resultIndex=1&disableRhsbl=true&format=0"
            mxtoolbox_headers = {
                "Tempauthorization": temp_auth_key,
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
            }
            response = self.query(spf_mxtoolbox_url, headers=mxtoolbox_headers)
            spf_response_json = response.json()
            #print(json.dumps(spf_response_json, indent=4, sort_keys=True))

            #--SAVE MXTOOLBOX SPF DATA--
            self.failures = spf_response_json["Failed"]
            self.warnings = spf_response_json["Warnings"]
            self.passed = spf_response_json["Passed"]
            self.record_content = str(spf_response_json["Information"][0]["Description"])
            self.information = spf_response_json["Information"]
            self.errors = spf_response_json["Errors"]
            self.timeouts = spf_response_json["Timeouts"]

            #--CHECK IF SPF CHECK FAILED--
            if self.failures == []:
                self.result = "PASS"
            else:
                self.result = "FAIL"

    def query(self, endpoint:str, headers:str="", impersonate:str="chrome110"):
        """
        -runs a GET request against the provided endpoint and returns the raw requests.Session() GET response
        -slowly retries up to 5 times if the request fails
        -impersontates chrome110 by default - this gets around TLS fingerprinting, as
        mxtoolbox will block any traffic (returns 401) using the requests library TLS fingerprint. 
        
        """
        session = requests.Session()
        retries = 5
        num_of_trys = 0
        while num_of_trys < retries:
            try:
                response = session.get(endpoint, headers=headers, impersonate=impersonate)
                response.raise_for_status() #check if the status isn't successful
                return response
            
            except requests.exceptions.HTTPError as http_err:
                if response.status_code == 401: #no need to retry if the error is 401
                    raise Exception(f"Unauthorized access to {endpoint}. Please check your credentials. - {response.status_code} - {response.reason} - {response.text}")
                num_of_trys += 1
                time.sleep(1)
            except Exception as err: #generic and unknown errors that don't fall under HTTPError
                raise Exception(f"Failed to query {endpoint} with error: {err}")
        #this exception will only trigger if num_of_trys is less than retries - i.e it tried 5 times
        raise Exception(f"Failed to query {endpoint} after 5 retries. Last HTTP status code: {response.status_code} - {response.reason} - {response.text}")
            
class dmarc_check:
    def __init__(self, domain:str):
        self.result = None
        #domain arg must be a string and cannot be empty
        if type(domain) is not str:
            raise Exception("Domain must be a string.")
        elif domain is None:
            raise Exception("Domain cannot be empty.")
        else:
            self.domain = domain
        
        #DO SPF CHECKS
        self.check_dmarc()
        

    def check_dmarc(self):
            """
            Queries MXToolbox DMARC Check .
            Checks for failed MXtoolbox checks.
            """
            
            #--QUERY MXTOOLBOX FOR DMARC--
            #mxtoolbox requires authentication to query their tools
            #they do provide a free API, but you'll need an API key
            #using this method is more user friendly as it automatically generates a temporary authentication key

            #this will query mxtoolbox for a temporary authentication key
            temp_auth_mxtoolbox_url = f"https://mxtoolbox.com/api/v1/user"
            temp_auth = self.query(temp_auth_mxtoolbox_url)
            temp_auth_json = temp_auth.json()
            #print(json.dumps(temp_auth_json, indent=4, sort_keys=True))
            temp_auth_key = temp_auth_json["TempAuthKey"]
                
            #this will run the MXToolbox DKIM check
            dmarc_mxtoolbox_url = f"https://mxtoolbox.com/api/v1/lookup?command=dmarc&argument={self.domain}&resultIndex=1&disableRhsbl=true&format=0"
            mxtoolbox_headers = {
                "Tempauthorization": temp_auth_key,
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
            }
            response = self.query(dmarc_mxtoolbox_url, headers=mxtoolbox_headers)
            dmarc_response_json = response.json()
            #print(json.dumps(dmarc_response_json, indent=4, sort_keys=True))

            #--SAVE MXTOOLBOX SPF DATA--
            self.failures = dmarc_response_json["Failed"]
            self.warnings = dmarc_response_json["Warnings"]
            self.passed = dmarc_response_json["Passed"]
            self.record_content = str(dmarc_response_json["Information"][0]["Description"])
            self.information = dmarc_response_json["Information"]
            self.errors = dmarc_response_json["Errors"]
            self.timeouts = dmarc_response_json["Timeouts"]

            #--CHECK IF SPF CHECK FAILED--
            if self.failures == []:
                self.result = "PASS"
            else:
                self.result = "FAIL"

    def query(self, endpoint:str, headers:str="", impersonate:str="chrome110"):
        """
        -runs a GET request against the provided endpoint and returns the raw requests.Session() GET response
        -slowly retries up to 5 times if the request fails
        -impersontates chrome110 by default - this gets around TLS fingerprinting, as
        mxtoolbox will block any traffic (returns 401) using the requests library TLS fingerprint. 
        
        """
        session = requests.Session()
        retries = 5
        num_of_trys = 0
        while num_of_trys < retries:
            try:
                response = session.get(endpoint, headers=headers, impersonate=impersonate)
                response.raise_for_status() #check if the status isn't successful
                return response
            
            except requests.exceptions.HTTPError as http_err:
                if response.status_code == 401: #no need to retry if the error is 401
                    raise Exception(f"Unauthorized access to {endpoint}. Please check your credentials. - {response.status_code} - {response.reason} - {response.text}")
                num_of_trys += 1
                time.sleep(1)
            except Exception as err: #generic and unknown errors that don't fall under HTTPError
                raise Exception(f"Failed to query {endpoint} with error: {err}")
        #this exception will only trigger if num_of_trys is less than retries - i.e it tried 5 times
        raise Exception(f"Failed to query {endpoint} after 5 retries. Last HTTP status code: {response.status_code} - {response.reason} - {response.text}")
      
def do_all_checks(domain:str, selector:str|list=None) -> dict:
    """
    Runs all checks for a domain.
    Returns a dictionary of the results.
    """
    results = {}
    results["domain"] = domain
    results["dkim"] = dkim_check(domain, selector)
    results["spf"] = spf_check(domain)
    results["dmarc"] = dmarc_check(domain)
    return results

def print_into_coulmns(list_:list, num_columns:int=2, colour:str=""):
    """
    Prints a list into the provided number of columns.
    """
    if type(list_) is not list:
        raise Exception(f"Argument 'list' must be a list data type. - {type(list_)}")
    
    if type(num_columns) is not int:
        raise Exception("Argument 'num_columns' must be an integer data type.")

    # Calculate the number of rows needed
    num_rows = -(-len(list_) // num_columns)

    # Iterate through the rows and print the list items into columns
    for row in range(num_rows):
        for col in range(num_columns):
            index = row + col * num_rows
            if index < len(list_):
                print(f"{colour}{list_[index]:<20}", end="")
        print()  # Move to the next line for the next row

def main():
    parser = argparse.ArgumentParser(description='')
    parser.add_argument('-d', '--domain', dest='domain', help='Domain Name you want to test.', required=True)
    parser.add_argument('-s', '--selector', dest='selector', help='DKIM Selector, can be extracted from email.', required=False)
    parser.add_argument('-v', '--verbose', dest='verbose', help='Print detailed results.', action='store_true', required=False)
    #parser.add_argument('-j', '--json', dest='json', help='Print results in JSON format.', action='store_true', required=False)
    #parser.add_argument('-o', '--output', dest='output', help='Output results to a file.', required=False)
    args = parser.parse_args()

    #if -j used, default will be use json.dumps to print to stdout
    #if -o used, default will be print to file
    #if -v used, default will be print detailed results

    #if -o and -j used, default will be print to file in json format
    #if -o and -v used, default will be print to file in detailed format

    #if -j and -v used, raise exception
    #if args.json and args.verbose:
    #    raise Exception("Cannot use both -j (--json) and -v (--verbose) arguments.")
    


    OKGREEN = '\033[92m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    ENDC = '\033[0m'
    FAIL = '\033[91m'
    PURPLE = '\033[95m'
    WARNING = '\033[93m'
    UNDERLINE_BLUE = '\033[4;34m'


    #dkim = dkim_check("rsolutions.com")
    #print(f"{dkim.domain} - Result: {dkim.result} - Warnings: {dkim.warnings} - Failures: {dkim.failures} - Passed: {dkim.passed}")
    
    #spf = spf_check("rsolutions.com")
    #print(f"{spf.domain} - Result: {spf.result} - Warnings: {spf.warnings} - Failures: {spf.failures} - Passed: {spf.passed}")
    
    #dmarc = dmarc_check("rsolutions.com")
    #print(f"{dmarc.domain} - Result: {dmarc.result} - Warnings: {dmarc.warnings} - Failures: {dmarc.failures} - Passed: {dmarc.passed}")

    list_indent = " -  "
    indent = "    "
    print(f"[*] Running DMARC, DKIM, and SPF checks for {str(args.domain)}...")
    
    if args.selector:
        print(f"[*] Using DKIM selector {PURPLE}{str(args.selector)}{ENDC}")
        results = do_all_checks(str(args.domain), str(args.selector))

    else:
        results = do_all_checks(str(args.domain))
        #print DKIM selectors found for the domain
        print(f"[*] Found {len(results['dkim'].selectors)} DKIM selector(s) for {str(args.domain)}:")
        
        selector_names = []
        for selector in results['dkim'].selectors:
            selector_names.append(str(selector['name']))
        print_into_coulmns(selector_names, colour=f"{list_indent}{PURPLE}")

    #Pretty DKIM Results
    if results["dkim"].result == "FAIL":
        print(f"{ENDC}[*] DKIM Check: {FAIL}{results['dkim'].result}{ENDC}")
    else:
        print(f"{ENDC}[*] DKIM Check: {OKGREEN}{results['dkim'].result}{ENDC}")
    
    if args.verbose:
        for selector in results['dkim'].selectors:
            print(f"{indent}{UNDERLINE_BLUE}{selector['name']}:{ENDC}")
            print(f"{indent}{indent}{FAIL}Failed: {ENDC}{selector['failed']}")
            print(f"{indent}{indent}{WARNING}Warnings: {ENDC}{selector['warnings']}")
            print(f"{indent}{indent}{OKBLUE}Passed: {ENDC}")
            for pass_check in selector['passed']:
                print(f"{indent}{indent}{indent}{OKGREEN}* {OKCYAN}{pass_check['Name']}{ENDC}")
    
    #Pretty SPF Results    
    if results["spf"].result == "FAIL":
        print(f"{ENDC}[*] SPF Check: {FAIL}{results['spf'].result}{ENDC}")
    else:
        print(f"{ENDC}[*] SPF Check: {OKGREEN}{results['spf'].result}{ENDC}")
    
    if args.verbose:
        print(f"{indent}{FAIL}Failed: {ENDC}{results['spf'].failures}")
        print(f"{indent}{WARNING}Warnings: {ENDC}{results['spf'].warnings}")
        print(f"{indent}{OKBLUE}Passed: {ENDC}")
        for pass_check in results['spf'].passed:
            print(f"{indent}{indent}{OKGREEN}* {OKCYAN}{pass_check['Name']}{ENDC}")
    
    #Pretty DMARC Results
    if results["dmarc"].result == "FAIL":
        print(f"{ENDC}[*] DMARC Check: {FAIL}{results['dmarc'].result}{ENDC}")
    else:
        print(f"{ENDC}[*] DMARC Check: {OKGREEN}{results['dmarc'].result}{ENDC}")

    if args.verbose:
        print(f"{indent}{FAIL}Failed: {ENDC}{results['dmarc'].failures}")
        print(f"{indent}{WARNING}Warnings: {ENDC}{results['dmarc'].warnings}")
        print(f"{indent}{OKBLUE}Passed: {ENDC}")
        for pass_check in results['dmarc'].passed:
            print(f"{indent}{indent}{OKGREEN}* {OKCYAN}{pass_check['Name']}{ENDC}")
    
if __name__ == "__main__":
    main()

#TODO
#DKIM
    #convert each selector to a subclass of dkim_check
        #convert each selector dictionary key to a class attribute
#General
    #check if the record MXToolbox returns matches the record returned by a DNS query - DKIM, SPF, DMARC
        #sometimes MXToolbox has old records cached
    
    #make each DKIM, DMARC, SPF check class a subclass of a general check class
        # - can call all the checks from one class, while still being able to call each check individually
        # - reduces the need to re-create the query function for each check, also gets rid of the domain
        #   check in each __init__ 
        # - queries to "https://mxtoolbox.com/api/v1/user" for a temp auth key can be done once and stored
        # - dynamically output results if all checks use the same attributes/format
    
    #add option to output in json
    #add option to output to file
        #output in json or detailed format to a file
    
    #add a check for the domain's MX records

    #allow users to use their MXToolbox API key instead of generating a temp auth key
        #requires whole new endpoint for queries
    

    
