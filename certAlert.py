#!/usr/bin/env python
import datetime, sys, re, urllib2, logging
import pushnotify
from bs4 import BeautifulSoup

ERRSTR = '!!!!!!!!!!!!! '

PUSHOVER_DEVICE = 'chromehome'

TARGET_URL = 'https://www.cert-bund.de/overview/AdvisoryShort'
MEMORY_PATH = 'C:\Users\Panki\Desktop\Privat\Dev\certAlert\out.txt'

USER_KEY_PATH = 'C:\Users\Panki\Desktop\Privat\Dev\pushover_user'
API_KEY_PATH = 'C:\Users\Panki\Desktop\Privat\Dev\pushover_key'

PROGRAMS = [u'Chrome', u'OpenSSH', u'Java', u'Linux', u'Apache', u'Windows']

with open(USER_KEY_PATH, 'r') as userKeyFile:
        USER_KEY = userKeyFile.read()
        userKeyFile.close()
with open(API_KEY_PATH, 'r') as apiKeyFile:
    API_KEY = apiKeyFile.read()
    userKeyFile.close()

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
    logger = logging.getLogger('pushnotify')
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(name)s-%(levelname)s: %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)

   
def main():
    import pushnotify
    startLogger()
    #readKeys()
    client = pushnotify.get_client('pushover', API_KEY, 'certAlert')
    client.add_key(USER_KEY, PUSHOVER_DEVICE)
    try:
        response = urllib2.urlopen(TARGET_URL)
    except:
        e = sys.exc_info()[0]
        print(ERRSTR + 'Error getting Webpage!\r\n' + e)
        sys.exit(ERRSTR + 'Stopping execution!')
    html = response.read()
    soup = BeautifulSoup(html, 'html.parser')

    results = [] 
    for adv in soup.find_all('tr', {'class' : re.compile('search-result-*')}):
        x = Advisory(adv)
        results.append(x)
    try:
        with open(MEMORY_PATH, 'r') as memFile:
            checkedIDs = memFile.read() 
            memFile.close()
    except IOError:
        print(ERRSTR + 'Error reading memory file!')
        print(ERRSTR + 'Continuing without list of checked IDs...')
        checkedIDs = ''
    except:
        e = sys.exc_info()[0]
        print('An unknown error occured!')
        print(e)
    for result in results:
        if result.risk > 3:
            for prog in PROGRAMS:
                if re.match(prog, result.description, re.IGNORECASE):
                    if result.identifier not in checkedIDs:
                        #this means we have found an alert that we have not seen before! lets alert the user...
                        client.notify(result.description, result.identifier, kwargs={'priority': 1, 'url': result.link,'url_title': result.identifier});
                        result.debug()
                        print('========================================================================')
                    else:
                        print('Already sent an alert for ' + result.identifier +', skipping...')
    with open(MEMORY_PATH, 'w') as memFile:
        for result in results:
            memFile.write(result.identifier + '\r\n')
        memFile.close()


if __name__ == '__main__':
    main()