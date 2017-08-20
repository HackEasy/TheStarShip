#Pain.py Made By Th3 M3nT4l H0sP1t4l
#Coded By The M4d Sc13nT15t
#Can You Hear Those Voices?
#Look Into My Eyes Can You See The Pain
#The Chaos I Bring, Youll Never Forget My Name
#The Troubles, The Pain, The Panic, The Fear
#Im Not Santa, But Ill Be Around All Yea
#The Starship

The Starship is a tactical reconnaissance tool which aims to gather enough information about a target protected by CloudFlare in the hopes of discovering the location of the server. Using Tor to mask all requests, the tool as of right now has 3 different attack phases.

1. Misconfigured DNS scan using DNSDumpster.com.
2. Scan the Crimeflare.com database.
3. Bruteforce scan over 2500 subdomains.

> Please feel free to contribute to this project. If you have an idea or improvement issue a pull request!

#### Disclaimer
This tool is only for academic purposes and testing  under controlled environments. Do not use without obtaining proper authorization
from the network owner of the network under testing.
The author bears no responsibility for any misuse of the tool.

#### Usage

To run a scan against a target:

```python Starship.py --target seo.com```

To run a scan against a target using Tor:

```service tor start```

(or if you are using Windows or Mac install vidalia or just run the Tor browser)

```python Starship.py --target seo.com --tor```


Update >>> headers_useragents=[]  Has been added
