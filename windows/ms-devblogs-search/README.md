# Microsoft Developer Blogs Search

This sections provides the outputs of grepping Old New Thing articles for the terms "loader lock" and "DllMain". The comprehensive search is helpful for learning about the relevant Windows internals, backstory, and for reverse engineering.

For the search script, see the [Microsoft Developer Blogs Search repo](https://github.com/ElliotKillick/ms-devblogs-search).

Grep articles:

```shell
grep -rIni -B5 -A5 DllMain > ../dllmain.txt
```

```shell
grep -rIni -B5 -A5 "loader lock" > ../loader-lock.txt
```
