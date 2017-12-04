# certAlert, the NetSec info push script

Hey there. This is my little script which alerts me via Firebase Cloud Messageging (push) if there is a new advisory on the german CERT page which is relevant to my interests.

Adapting this for your own purposes shouldn't be too hard.
To use this, simply change the constants at the head of the file.
Requires BeautifulSoup and pyfcm! Huge shoutout to the creators of those.
Run this script as a cronjob on your server. Prolly need an android/ios app to receive this stuff tho

This _almost_ has the potential to become a crawler.