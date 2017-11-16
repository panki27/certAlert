#!/usr/bin/env python
import datetime, sys, re, urllib2, logging
import pushnotify
#TODO: replace pushnotify with a simple HTTP_POST
from bs4 import BeautifulSoup

ERRSTR = '!!!!!!!!!!!!! '




# REMEMBER TO CHANGE THESE!!!
TARGET_URL = 'https://www.cert-bund.de/overview/AdvisoryShort'
MEMORY_PATH = 'C:\Users\Panki\Desktop\Privat\Dev\certAlert\out.txt'

#TODO: Put all this in a single file
USER_KEY_PATH = 'C:\Users\Panki\Desktop\Privat\Dev\pushover_user'
API_KEY_PATH = 'C:\Users\Panki\Desktop\Privat\Dev\pushover_key'
PUSHOVER_DEVICE = 'chromehome'

# To monitor more programs, simply add a string here
PROGRAMS = [u'Chrome', u'OpenSSH', u'Java', u'Linux', u'Apache', u'Windows']

with open(USER_KEY_PATH, 'r') as userKeyFile:
        USER_KEY = userKeyFile.read()
        userKeyFile.close()
with open(API_KEY_PATH, 'r') as apiKeyFile:
    API_KEY = apiKeyFile.read()
    userKeyFile.close()

# object to store a single cert alert
class Advisory:
    def __init__(self, html):
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
    # thanks to whoever i stole this from
    logger = logging.getLogger('pushnotify')
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(name)s-%(levelname)s: %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)

def getHTML(url):
    try:
        response = urllib2.open(url)
    except urllib2.URLError:
        print(ERRSTR + 'Failed getting webpage!')
        print(ERRSTR + 'Check your internet connection or TARGET_URL.')
        sys.exit(ERRSTR + 'Stopping execution!')
    except:
        e = sys.exc_info()[0]
        print(ERRSTR + 'Error getting Webpage!')
        print(e)
        sys.exit(ERRSTR + 'Stopping execution!')
    result = response.read();
    return result
   
def main():
    import pushnotify
    startLogger()
    client = pushnotify.get_client('pushover', API_KEY, 'certAlert')
    client.add_key(USER_KEY, PUSHOVER_DEVICE)
    #try:
    #    response = urllib2.urlopen(TARGET_URL)
    #except urllib2.URLError:
    #    print(ERRSTR + 'Failed getting webpage!')
    #    print(ERRSTR + 'Check your internet connection or TARGET_URL.')
    #    sys.exit(ERRSTR + 'Stopping execution!')
    #except:
    #    e = sys.exc_info()[0]
    #   print(ERRSTR + 'Error getting Webpage!')
    #    print(e)
    #    sys.exit(ERRSTR + 'Stopping execution!')
    #html = response.read()
    html = getHTML(TARGET_URL)
    soup = BeautifulSoup(html, 'html.parser')
    # create a list of results and add objects created with the data of each table row
    results = [] 
    for adv in soup.find_all('tr', {'class' : re.compile('search-result-*')}):
        x = Advisory(adv)
        results.append(x)
    # here we're checking which advisory IDs we've already seen, 
    # so we don't send multiple notifications for the same advisory
    # TODO: refactor into functions writeMemory(checkeIDs), readMemory()
    try:
        with open(MEMORY_PATH, 'r') as memFile:
            checkedIDs = memFile.read() 
            memFile.close()
    except IOError:
        # this most likely means file not found. this can happen during the first run
        print(ERRSTR + 'Error reading memory file!')
        print(ERRSTR + 'Continuing without list of checked IDs...')
        checkedIDs = ''
    except:
        e = sys.exc_info()[0]
        print('An unknown error occured!')
        print(e)
    for result in results:
        if result.risk > 3:
            # here we're checking if the is related to our programs
            for prog in PROGRAMS:
                if re.match(prog, result.description, re.IGNORECASE):
                    if result.identifier not in checkedIDs:
                        #this means we have found an alert that we have not seen before! lets alert the user...
                        client.notify(result.description, result.identifier, kwargs={'priority': 1, 'url': result.link,'url_title': result.identifier});
                        result.debug()
                        print('========================================================================')
                    else:
                        print('Already sent an alert for ' + result.identifier +', skipping...')
    # now we overwrite our memory file with the IDs we just checked
    with open(MEMORY_PATH, 'w') as memFile:
        for result in results:
            memFile.write(result.identifier + '\r\n')
        memFile.close()


if __name__ == '__main__':
    main()