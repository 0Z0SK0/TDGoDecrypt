# TDGoDecrypt
Golang package to decrypt Telegram Desktop tdata files

Telegram Desktop (desktop version) has a "tdata" folder where it stores some encrypted files.

This folder is found at "%USERPROFILE%\AppData\Roaming\Telegram Desktop".

This package can decrypt those files, which contains settings and cache files.

## Installation

```shell
go get github.com/0z0sk0/tdgodecrypt
```

## Credit
The original code and idea belongs to: [https://github.com/atilaromero/telegram-desktop-decrypt](https://github.com/atilaromero/telegram-desktop-decrypt)
