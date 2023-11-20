# CryptTool

## Installation and setup

If it's an Ubuntu system, you can install dependencies using the following command:

```
$ sudo apt-get install default-jdk-headless git build-essential cmake libgmp-dev pkg-config libssl-dev libboost-dev libboost-program-options-dev
```

Install antlr4:

```
$ pip install antlr4-tools
```

This project requires installing Python 3.8 or above. 

Additionally, the project uses antlr4 as the syntax parser, so it's necessary to install the antlr4 Python 3 runtime library:

```
$ pip3 install antlr4-python3-runtime
```

## Usage

Run:

```
$ antlr4 -Dlanguage=Python3 -listener Cryptlang.g4
```

```
$ python main.py <cryptlang-input> <solidity-output>
```

For example:

```
$ python main.py ECDSA/Permit.crypt ECDSA/Permit.sol
```

This command translates CryptLang code in 'ECDSA/Permit.crypt' to Solidity code in 'ECDSA/Permit.sol'.