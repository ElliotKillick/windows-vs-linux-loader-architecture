#!/usr/bin/python3

from pathlib import Path
import os
import re
import requests
from lxml import etree

PROGRAM_DIRECTORY = Path(__file__).parent.resolve()

# Configuration variables
# Right now, we're specifically searching for Old New Thing articles
# We append a page number to this base URL
PAGE_LISTING_BASE_URL = "https://devblogs.microsoft.com/oldnewthing/page/"
OUTPUT_DIRECTORY = PROGRAM_DIRECTORY / "articles"

os.mkdir(OUTPUT_DIRECTORY)

# Server may block Python Requests user-agent so report to be curl instead
headers = {
    'User-Agent': 'curl/8.0.1'
}

page_number = 1

while True:
    listing_response = requests.get(f"{PAGE_LISTING_BASE_URL}{page_number}", headers=headers)
    # Read until 404 status or another non-success status
    if listing_response.status_code != 200:
        exit(0)

    print(f"Page: {page_number}")

    # I've confirmed (by testing with a payload) that HTMLParser is NOT vulnerable to XXE
    # https://bugs.launchpad.net/lxml/+bug/1742885
    # https://lxml.de/4.0/api/lxml.etree.HTMLParser-class.html
    listing_html = listing_response.content
    listing_tree = etree.fromstring(listing_html, etree.HTMLParser())
    entry_links = listing_tree.iterfind("body//main//article//header//h2/a")

    for entry_link in entry_links:
        link = entry_link.get("href")
        print(f"Link: {link}")

        entry_html = requests.get(link, headers=headers).content
        entry_tree = etree.fromstring(entry_html, etree.HTMLParser())
        article_tree = entry_tree.find("body//main//article")
        article_text = ''.join(article_tree.itertext())

        # Use article path substring as its identifier
        article_path_part = ''.join(link.split("/")[-2:])
        # Filter for alphanumeric characters only to prevent a local file inclusion vulnerability
        article_file_name = re.sub("[^\da-zA-Z]", "", article_path_part)

        # Store article then grep later because there are lots of articles
        # So, we want to reduce slow network I/O
        with open(f"{OUTPUT_DIRECTORY}/{article_file_name}", 'w') as article_file:
            article_file.write(article_text)

    page_number += 1
