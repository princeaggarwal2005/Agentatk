class FakeNet:
    def __init__(self):
        self.pages = {}
        self.requests = []

    def serve_page(self, url, content):
        self.pages[url] = content

    def request(self, method, url, body=""):
        self.requests.append({"method": method, "url": url, "body": body})
        if url in self.pages:
            return 200, self.pages[url]
        return 404, "not found"