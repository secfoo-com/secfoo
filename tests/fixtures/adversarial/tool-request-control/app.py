from urllib.request import urlopen

def preview_link(user_url):
    return urlopen(user_url).read()
