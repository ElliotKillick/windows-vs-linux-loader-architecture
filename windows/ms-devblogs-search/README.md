# Microsoft Development Blogs Search

This section provides a Python script for downloading Microsoft devblogs articles. We then comprehensively search the text of the downloaded articles.

DevBlogs has RSS feeds but they only store back to the last few articles. The DevBlogs site uses Wordpress (on the WP Engine platform, according to the HTTP `x-powered-by` response header), so we can't pull from a GitHub repo either. Google can be hit-or-miss. Hence, we must search articles by parsing the website's HTML and grabbing each one individually.

Grep articles:

```shell
grep -rIni DllMain > ../loader-lock.txt
```

```shell
grep -rIni "loader lock" > ../dllmain.txt
```
