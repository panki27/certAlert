#!/bin/env/python
import datetime, sys, re, urllib2
from bs4 import BeautifulSoup

TARGET_URL = 'https://www.cert-bund.de/overview/AdvisoryShort'
MEMORY_PATH = 'C:\Users\Panki\Desktop\Privat\Dev\certAlert\out.txt'
PROGRAMS = [u'Chrome', u'OpenSSH', u'Java', u'Linux']
class Advisory:
    def __init__(self, html):

        self.date = datetime.datetime.strptime(html.td.text, '%d.%m.%y').date()
        self.risk = int(html.find('span', {'class': re.compile('search-result-crit-*')}).text)
        self.identifier = html.find('a', {'class': 'search-result-link'}).text
        self.link = TARGET_URL + html.find('a', {'class': 'search-result-link'})['href']
        self.description = html.find_all('a', {'class': 'search-result-link'})[1].text 
    def debug(self):
        print('date: '+ self.date.isoformat())
        print('risk: '+ str(self.risk))
        print('id: ' + self.identifier)
        print('desc: ' + self.description)
        print('link: ' + self.link)

try:
    response = urllib2.urlopen(TARGET_URL)
except:
    e = sys.exc_info()[0]
    print('Error getting Webpage!\r\n' + e)
    sys.exit('Stopping execution!')
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
    print('Error reading memory file!')
    print('Continuing without list of checked IDs...')
    checkedIDs = ''
except:
    e = sys.exc_info()[0]
    print('An unknown error occured!')
    print(e)
for result in results:
    if result.risk > 3:
        for prog in PROGRAMS:
            if re.match(prog, result.description):
                if result.identifier not in checkedIDs:
                    result.debug()
                    print('==================================')
                else:
                    print('Already sent an alert for ' + result.identifier +', skipping...')
with open(MEMORY_PATH, 'w') as memFile:
    for result in results:
        memFile.write(result.identifier + '\r\n')
    memFile.close()