# Pirate


## Web/Pirate

Author: iLoop


### Description

This one is simple you just need to get the /flag :-)


### First Try

    $ curl -s http://io.ept.gg:30070/flag  
    Forbidden, but nice try ;)


### Filter

    from mitmproxy import http
    import re
    
    
    def request(flow):
        if 'flag' in flow.request.url:
            flow.response = http.HTTPResponse.make(403, b"Forbidden, but nice try ;)


### Second Try

    $ curl -s http://io.ept.gg:30070/fl%61g  
    EPT{5mugl3r5_liv3_l1k3_k1ng5}
