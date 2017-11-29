#!/usr/bin/env python
import datetime, sys, re, urllib2, logging
#before running this you might want to export PYTHONIOENCODING=UTF-8
#TODO: replace pushnotify with a simple HTTP_POST
from bs4 import BeautifulSoup
from pyfcm import FCMNotification


ERRSTR = '!!!!!!!!!!!!! '

# REMEMBER TO CHANGE THESE!!!
TARGET_URL = 'https://www.cert-bund.de/overview/AdvisoryShort'
MEMORY_PATH = 'C:\Users\Panki\Desktop\Privat\Dev\certAlert\out.txt'

#TODO: Put all this in a single file
USER_KEY_PATH = 'C:\Users\Panki\Desktop\Privat\Dev\pushover_user'
API_KEY_PATH = 'C:\Users\Panki\Desktop\Privat\Dev\pushover_key'
REG_KEYS_PATH = 'C:\Users\Panki\Desktop\Privat\Dev\device_list'


# To monitor more programs, simply add a string here
PROGRAMS = [u'Git', u'Chrome', u'OpenSSH', u'Java', u'Linux', u'Apache', u'Windows']

with open(USER_KEY_PATH, 'r') as userKeyFile:
    USER_KEY = userKeyFile.read()
    userKeyFile.close()
with open(API_KEY_PATH, 'r') as apiKeyFile:
    API_KEY = apiKeyFile.read()
    apiKeyFile.close()
with open(REG_KEYS_PATH, 'r') as regKeyFile:
    REG_KEYS = regKeyFile.readlines()
    regKeyFile.close()

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
    import urllib2
    try:
        response = urllib2.urlopen(url)
    except URLError:
        print(ERRSTR + 'Failed getting webpage!')
        print(ERRSTR + 'Check your internet connection or TARGET_URL.')
        sys.exit(ERRSTR + 'Stopping execution!')
    except:
        e = sys.exc_info()[0]
        print(ERRSTR + 'Error getting Webpage!')
        print(e)
        sys.exit(ERRSTR + 'Stopping execution!')
    result = response.read()
    return result
   
def main():
    #import pushnotify
    #startLogger()
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
                if re.search(prog, result.description, re.IGNORECASE):
                    if result.identifier not in checkedIDs:
                        #this means we have found an alert that we have not seen before! lets alert the user...
                        for key in REG_KEYS:
                            print(type(key))
                            try:

                                response = client.notify_single_device(registration_id=key, message_body=result.description, message_title=result.identifier)
                            except:
                                e = sys.exc_info()[0]
                                print(e)
                                print("we fucked up!")
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