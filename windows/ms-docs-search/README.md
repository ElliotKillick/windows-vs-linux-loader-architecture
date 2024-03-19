# Microsoft Documentaion Search

This section intends to document all the places where Microsoft documentation mentions `DllMain` or loader lock.

Get Microsoft documentation repos:

```
git clone https://github.com/MicrosoftDocs/win32
git clone https://github.com/MicrosoftDocs/sdk-api
git clone https://github.com/MicrosoftDocs/cpp-docs
```

Grep each repo:

```shell
grep -rIni DllMain > ../<OUTPUT_FILE>
```

```shell
grep -rIni "loader lock" > ../<OUTPUT_FILE>
```
