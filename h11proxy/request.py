from urllib.parse import ParseResult, urlparse

import h11
import requests
from requests.structures import CaseInsensitiveDict


class ProxyRequest(object):
    def __init__(self):
        self.conn: h11.Connection = h11.Connection(h11.SERVER)
        self.proxies = {}
        self.scheme = None
        self.host = None
        self.port = None

    def get_url(self, event: h11.Request):
        path = event.target
        url: ParseResult = urlparse(path)

        if not url.scheme:
            url = url._replace(scheme=self.scheme.encode())

        if not url.netloc:
            url = url._replace(netloc=b'%s:%s' % (self.host, self.port))

        return url.geturl()

    def get_h11_headers(self, event: h11.Request):
        headers = CaseInsensitiveDict({k: v for k, v in event.headers})
        return headers

    def get_requests_headers(self, response: requests.Response):
        headers = [(k, v) for k, v in response.headers.items()]
        return headers
