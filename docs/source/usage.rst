##############
Usage examples
##############


For real-time examination of snort's alerts use `IPythonDataHandler` class::


    $ sudo python -m pigear --data-handler pigear.contrib.IPythonDataHandler
    ##################################################################################
    IPython data handler initialized.
    On Snort's alert, IPython shell is spawned for you.
    Alert is present as ``msg`` variable in current scope.
    ##################################################################################

    Python 2.7.3 (default, Apr 20 2012, 22:44:07) 
    Type "copyright", "credits" or "license" for more information.

    IPython 0.12.1 -- An enhanced Interactive Python.
    ?         -> Introduction and overview of IPython's features.
    %quickref -> Quick reference.
    help      -> Python's own help system.
    object?   -> Details about 'object', use 'object??' for extra details.

    In [1]: msg.
    msg.caplen           msg.count            msg.msg                        
    msg.classification   msg.data             msg.nethdr                     
    msg.dlthdr           msg.event_reference  msg.priority         
    msg.event_id         msg.index            msg.sig_generator    
    msg.pkt              msg.transhdr         msg.ts_usec
    msg.pktlen           msg.ts_sec           msg.tv_sec 
    msg.sig_id           msg.tv_usec                     
    msg.sig_rev          msg.val                         

    In [1]: msg.priority
    Out[1]: 2

    In [2]: print(msg.msg)
    VOIP-SIP-UDP From header unquoted tokens in field attempt



Or if you want to send alerts as json to remote http server there's `HttpSendHandler` class,
you'll nedd `requests <https://github.com/kennethreitz/requests/>`_ for this::

   $ sudo python -m pigear --debug --data-handler pigear.contrib.HttpSendHandler url=http://httpbin.org/post
    Starting pigear ...
    DEBUG:pigear/core.pyc:
    msg: VOIP-SIP-UDP From header unquoted tokens in field attempt
    ts_sec: 1339630108
    ts_usec: 503703
    caplen: 348
    pktlen: 348
    dlthdr: 0
    nethdr: 14
    transhdr: 34
    data: 42
    val: 0
    sig_generator: 1
    sig_id: 20326
    sig_rev: 1
    classification: 7
    priority: 2
    event_id: 1
    event_reference: 1
    tv_sec: 1339630108
    tv_usec: 503703
    INFO:requests.packages.urllib3.connectionpool:Starting new HTTP connection (1): httpbin.org
    DEBUG:requests.packages.urllib3.connectionpool:"POST /post HTTP/1.1" 200 89649
    INFO:pigear/contrib/http_sender.pyc:{
    "origin": "194.160.28.51",
    "files": {},
    "form": {
        "alert": "{
            \"msg\": \"VOIP-SIP-UDP From header unquoted tokens in field attempt 
            ...
            \"pkt\": \"AAAAAAAAAAAAAAAACABFAAFOAAB
            ...
            ...
            ...
            \"sig_generator\": 1,
            \"sig_id\": 20326,
            \"sig_rev\": 1,
            \"classification\": 7,
            \"priority\": 2,
            \"event_id\": 1, \"event_reference\": 1,
            \"tv_sec\": 1339630108,
            \"tv_usec\": 503703
        }"
    },
    "url": "http://httpbin.org/post",
    "args": {},
    "headers": {
        "Content-Length": "89534",
        "Accept-Encoding": "identity, deflate, compress, gzip",
        "Connection": "keep-alive",
        "Accept": "*/*",
        "User-Agent": "python-requests/0.9.1",
        "Host": "httpbin.org",
        "Content-Type": "application/x-www-form-urlencoded"
    },
    "json": null,
    "data": ""
    }
