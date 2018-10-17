#!/usr/bin/env python
# before running this you might want to export PYTHONIOENCODING=UTF-8, or add it permanently to /etc/environment
import datetime, sys, re, urllib2, logging
from bs4 import BeautifulSoup
from pyfcm import FCMNotification

ERRSTR = '!!!!!!!!!!!!! '

# REMEMBER TO CHANGE THESE!!!
TARGET_URL = 'https://www.cert-bund.de/overview/AdvisoryShort'

MEMORY_PATH = 'C:\Users\Panki\Desktop\Privat\Dev\certAlert\out.txt'
KEY_FILE_PATH = 'C:\Users\Panki\Desktop\Privat\Dev\keyfile'

# To monitor more programs, simply add a string here
PROGRAMS = [u'Android', u'Git', u'Chrome', u'OpenSSH', u'Java', u'Linux', u'Apache', u'Windows']

# object to store a single cert alert
class Advisory:
    def __init__(self, html):
        # this is the fun parts. here we 'fish' the information out of the HTML
        self.date = datetime.datetime.strptime(html.td.text, '%d.%m.%y').date()
        self.risk = int(html.find('span', {'class': re.compile('search-result-crit-*')}).text)
        self.identifier = html.find('a', {'class': 'search-result-link'}).text
        self.link = 'https://www.cert-bund.de/' + html.find('a', {'class': 'search-result-link'})['href']
        self.description = html.find_all('a', {'class': 'search-result-link'})[1].text 
    def debug(self):
        print('date: '+ self.date.isoformat())
        print('risk: '+ str(self.risk))
        print('id: ' + self.identifier)
        print('desc: ' + self.description)
        print('link: ' + self.link)

def startLogger():
    # todo: figure out how this works?
    # thanks to whoever i stole this from
    logger = logging.getLogger('certAlert')
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(name)s-%(levelname)s: %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)

def getHTML(url):
    import urllib2
    try:
        response = urllib2.urlopen(url)
    except URLError:
        print(ERRSTR + 'Failed getting webpage!')
        print(ERRSTR + 'Check your internet connection or TARGET_URL.')
        sys.exit(ERRSTR + 'Stopping execution!')
    except:
        e = sys.exc_info()[1]
        print(ERRSTR + 'Error getting Webpage!')
        print(e)
        sys.exit(ERRSTR + 'Stopping execution!')
    result = response.read()
    return result

def readFile(path, lines = False):
    try:
        with open(path, 'r') as file:
            if(lines):
                contents = file.readlines()
            else:
                contents = file.read()
            file.close()
    except IOError:
        # this most likely means file not found. this can happen during the first run
        print(ERRSTR + 'Error reading file ' + path + '!')
        contents = ''
    except:
        e = sys.exc_info()[1]
        print('An unknown error occured!')
        print(e)
        contents = ''
    finally:
        return contents

def main():
# this loads our API keys into memory from an external file which is specified above
    try:
        contents = readFile(KEY_FILE_PATH, True)
        # extract just the text behind the equals sign
        API_KEY = contents[0].split("=",1)[1]
        USER_KEYS = contents[1].split("=",1)[1]
        # get rid of that pesky newline
        API_KEY = API_KEY.strip()
        # now we split along semicolons to get single keys in a list
        USER_KEYS = USER_KEYS.split(";")
    except:
        e = sys.exc_info()[1]
        print(e)
        print(ERRSTR + "I couldn't load your credentials. Did you specify your keyfile?")
        sys.exit(ERRSTR + 'Stopping execution!')

    #startLogger()
    print('Getting client using ' + API_KEY)
    client = FCMNotification(api_key=API_KEY)
    html = getHTML(TARGET_URL)
    soup = BeautifulSoup(html, 'html.parser')
    # create a list of results and add objects created with the data of each table row
    results = [] 
    for adv in soup.find_all('tr', {'class' : re.compile('search-result-*')}):
        x = Advisory(adv)
        results.append(x)
    # here we're checking which advisory IDs we've already seen, 
    # so we don't send multiple notifications for the same advisory
    checkedIDs = readFile(MEMORY_PATH)
    for result in results:
        if result.risk > 3:
            # here we're checking if the is related to our programs
            for prog in PROGRAMS:
                if re.search(prog, result.description, re.IGNORECASE):
                    if ( len(checkedIDs) == 0 ) or ( result.identifier not in checkedIDs ):
                        #this means we have found an alert that we have not seen before! lets alert the user...
                        for key in USER_KEYS:
                            try:
                                key = key.rstrip()
                                response = client.notify_single_device(registration_id=key, message_body=result.description, message_title=result.identifier)
                            except:
                                e = sys.exc_info()[1]
                                print(e)
                                print("we fucked up!")
                        result.debug()
                        print('========================================================================')
                    else:
                        print('Already sent an alert for ' + result.identifier +', skipping...')
    # now we overwrite our memory file with the IDs we just checked
    with open(MEMORY_PATH, 'w') as memFile:
        for result in results:
            memFile.write(result.identifier + '\r')
        memFile.close()

if __name__ == '__main__':
    main()