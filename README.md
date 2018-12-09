# chanerator

The chanerator generates a bitmessage stream 1 chan address on the command line.

# usage

$ python chanerator.py *passphrase*

# bash

If your OS has bash, add this to .bashrc to create a bash command:

alias chan='python2 ~/$PATH/chanerator.py'

$PATH should be replaced with the directory path to chanerator.py

then usage would be: $ chan *passphrase*

# command line switches

    -h, --help         show this help message and exit
    -s, --stats        Show stats when complete
    -i, --info         Show license and author info.
    -l, --logo         Show logo and contact info.
    --openssl=LIBRARY  Path of OpenSSL library to use

# examples

    $ python chanerator.py bitmessage
    [BM-2cWy7cvHoq3f1rYMerRJp8PT653jjSuEdY]
    label = [chan] bitmessage
    enabled = true
    decoy = false
    chan = true
    noncetrialsperbyte = 1000
    payloadlengthextrabytes = 1000
    privsigningkey = 5K42shDERM5g7Kbi3JT5vsAWpXMqRhWZpX835M2pdSoqQQpJMYm
    privencryptionkey = 5HwugVWm31gnxtoYcvcK7oywH2ezYTh6Y4tzRxsndAeMi6NHqpA
    
    ./chanerator.py gonkulator
    [BM-2cXMNfGh68WbH2Eh7c5zYj7j8Jt8rtBvcE]
    label = [chan] gonkulator
    enabled = true
    decoy = false
    chan = true
    noncetrialsperbyte = 1000
    payloadlengthextrabytes = 1000
    privsigningkey = 5KXZprdQiFCtB3B8XE1n95BydrrZQ1gEN4VQMkoZRNxszxG7gek
    privencryptionkey = 5JDEp25pdi5xRC9UnzNhdatkHSQHxn7McJqubcXTvTosr8hpFJq
    
    with chanerator added to path:
    
    $ chan hello
	[BM-2cWhA72reAp1CBa8JmspqWRCdw93sDLgiS]
	label = [chan] hello
	enabled = true
	decoy = false
	chan = true
	noncetrialsperbyte = 1000
	payloadlengthextrabytes = 1000
	privsigningkey = 5Kj4516zcKRQuzn8g5N4Pha7BGN9YtQVosAATxmQt1mpD1JUsZE
	privencryptionkey = 5KE5Jzhv8geP4KJahkEBsuL5sSQsH7Fe1eDpui2FNWitYBrBkEC

    with multiple names:

    ./chanerator.py beef "steak dinner"
    
    [BM-2cUVjszE9Vt84xfJxgujgxncJraW4ARCP8]
    label = [chan] beef
    enabled = true
    decoy = false
    chan = true
    noncetrialsperbyte = 1000
    payloadlengthextrabytes = 1000
    privsigningkey = 5K7Ayng38xDbXE8amEHsubbF3jdm1fwMaTjbUE37JZj2sYxmRwT
    privencryptionkey = 5J1PvVEVM6ohjKm4HbGpPRr3MgTR96Wv44xKiFrMHXju1HsXGkc

    [BM-2cSx6uMGrc71Dtaje9AsdnW9Si2UZ7WGAE]
    label = [chan] steak dinner
    enabled = true
    decoy = false
    chan = true
    noncetrialsperbyte = 1000
    payloadlengthextrabytes = 1000
    privsigningkey = 5JEG37gmoNh9zr3Aytz494ohePF3v9LSQw2p3ew27R7kZiqbctw
    privencryptionkey = 5JtzMgSqjGycHX6rBva67mqsZSsHwtKMEksTyThPJAwmxUJSsCS
