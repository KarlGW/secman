# secman

> A CLI secret manager

`secman` is a command line tool for handling secrets (like passwords, credentials etc). The reason of this CLI
is to give the user control of where and how the secrets are stored, and to not rely on a third party on keeping
the secrets safe.

* [Introduction](#introduction)
* [Install](#install)
  * [Autocompletion](#autocompletion)
* [Usage](#usage)


## Introduction

The default (and initially only supported) storage method stores the secret collection in a file on a local (or network) filesystem.
This file is encrypted with AES-256-GCM and the key is generated by the CLI.

The secrets are each individually encrypted with AES-256-GCM with a key generated from a password set by the user.

These keys are stored in the credential manager/keychain of the OS the CLI is run on. These are:

* **Keychain** for macOS
* **Credential Manager (wincred)** for Windows
* **Secret Service (dbus)** for Linux

There are plans on plugins that enables the secrets to be stored on various storage providers. This does put
some reliance on a third party, but the case still stands; the keys for the collection and the secrets being
in the hands of the user.

## Install

Install scripts for the various OS are underway and worked upon. For now either:

* [Manual install](#manual-install) (download from [releases](https://github.com/KarlGW/secman/releases))
* [Use `go install`](#use-go-install)
* [Build from source](#build-from-source)

### Manual install

1. Go to [releases](https://github.com/KarlGW/secman/releases).
2. Download the archive that matches the systems operating system and architecture.
3. Extract the binary and move it to an appropriate target destination (preferably in `$PATH`):
```sh
# tar.gz
tar -xvf secman-<version>-<os>-<arch>.tar.gz && mv secman /path/to/target/directory
# zip
unzip secman-<version>-<os>-<arch>.zip && mv secman /path/to/target/directory
```

**Note**: The archive file contains the binary `secman` together with `README.md`, `LICENSE` and `LICENSE-THIRD-PARTY.md`.

### Use `go install`

```sh
go install github.com/KarlGW/secman
```

### Build from source

Building from source requires Go v1.21.1 installed on the system.

```sh
git clone github.com/KarlGW/secman
cd secman

OS=<os> # darwin, linux or windows.
ARCH=<arch> # amd64 or arm64.
GOOS=$OS GOARCH=$ARCH go build -ldflags="-w -s" -trimpath -o build/secman cmd/secman/main.go
```

### Autocompletion

To enable auto/tab completion for `secman` follow the steps below depending on shell.

**Bash**

Current session:

```sh
PROG=secman source <(secman completion bash)
```

For all sessions:

```sh
echo -e "\n# secman\nPROG=secman source <(secman completion bash)" >> ~/.bashrc
```

**Zsh**

Current session:

```sh
PROG=secman source <(secman completion zsh)
```

For all sessions:

```sh
echo -e "\n# secman\nPROG=secman source <(secman completion zsh)" >> ~/.zshrc
```

**PowerShell**

First create the autocompletion script:

```powershell
./secman completion powershell >> "$(Split-Path $PROFILE)/secman.ps1"
```

Current session:

```sh
& "$(Split-Path $PROFILE)/secman.ps1"
```

For all sessions:

```sh
"& $(Split-Path $PROFILE)/secman.ps1" >> $PROFILE
```

## Usage

### Initial setup

When using `secman` the key for the secret collection will be generated and set in the credential manager. Then
a "master password" must be used to generate the key for the secret.

```sh
secman profile set --password
```

This will prompt for a password. This will generate a key and set it in the credential manager, and this key will
be used for encrypting the secrets in the collection.

To update the password/key for all current and future secrets, run the command again.

### Adding a secret

**Set value from `stdin`**

```sh
secman secret create --name <name> --value <secret-value>
```

**Set value from clipboard**

```sh
secman secret create --name <name> --clipboard
```

### Retreive a secret

**List details of all secrets**

```sh
secman secret list
```

**Show details of a secret**

```sh
secman secret get --name <name>
```

**Get the value of the secret**

```sh
secman secret get --name <name> --decrypt
```

**Get the value of the secret and set to clipboard**

```sh
secman secret get --name <name> --decrypt --clipboard
```
(The value will not be shown, it will be available within the OS clipboard ready to be pasted where needed)

### Update a secret

**Update value from `stdin`**

```sh
secman secret update --name <name> --value <new-secret-value>
```

**Update value from clipboard**

```sh
secman secret update --name <name> --clipboard
```

### Delete a secret

```sh
secman secret delete --name <name>
```
