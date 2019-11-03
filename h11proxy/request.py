import gzip
import typing
from urllib.parse import urlsplit, urlunsplit

import h11
import requests
from requests.structures import CaseInsensitiveDict


class ProxyRequest(object):

    def __init__(self, event: (h11.Request, requests.Response), conn: h11.Connection):
        self._event = event
        self.headers: CaseInsensitiveDict = CaseInsensitiveDict()
        self.data = None

        self.proxies: typing.Dict = {}
        self.method = None
        self.scheme = None
        self.host = None
        self.port = None
        self.path = None

        self.status = None
        self.reason = None

        if isinstance(event, h11.Request):
            self.method = event.method.decode()
            self.headers.update({k.decode(): v for k, v in event.headers})

            if 'content-length' in self.headers:
                data_event = conn.next_event()
                assert isinstance(data_event, h11.Data)
                self.data = data_event.data
            else:
                self.data = None

            self.url = self._event.target.decode()

        elif isinstance(event, requests.Response):
            self.headers.update(event.headers)
            self.status = event.status_code
            self.reason = event.reason
            self.data = event.content
        else:
            raise NotImplementedError

    @property
    def url(self):
        if self.port:
            host = '{}:{}'.format(self.host, self.port)
        else:
            host = self.host

        url = urlunsplit((self.scheme, host, self.path or '', None, None))
        return url

    @url.setter
    def url(self, value):
        url = urlsplit(value, scheme='https', allow_fragments=False)

        if not url.netloc:
            host, *port = self.headers['host'].split(b':')
            host = host.decode()
        else:
            host, *port = url.netloc.split(':')

        self.scheme = url.scheme
        self.host = host
        if port:
            self.port = int(port[0])

        evt_host = self.headers['host'].decode()
        if url.path != evt_host:
            self.path = url.path
            if url.query:
                self.path += '?' + url.query
            if url.fragment:
                self.path += '#' + url.fragment

    @property
    def h11_headers(self):
        headers = [(k, v) for k, v in self.headers.items()]
        return headers
