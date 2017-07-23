# chanerator

The chanerator generates a bitmessage stream 1 chan address on the command line.

# usage

$ python2 chanerator.py *passphrase*

# bash

If your OS has bash, add this to .bashrc to create a bash command:


alias chan='python2 ~/$PATH/chanerator.py'


$PATH should be replaced with the directory path to chanerator.py


then usage would be: $ chan *passphrase*


# command line switches

-h help


-i license


-l logo

# examples

    $ python2 chanerator.py general
    [BM-2cW67GEKkHGonXKZLCzouLLxnLym3azS8r]
    label = [chan] general
    enabled = true
    decoy = false
    chan = true
    noncetrialsperbyte = 1000
    payloadlengthextrabytes = 1000
    privsigningkey = 5Jnbdwc4u4DG9ipJxYLznXSvemkRFueQJNHujAQamtDDoX3N1eQ
    privencryptionkey = 5JrDcFtQDv5ydcHRW6dfGUEvThoxCCLNEUaxQfy8LXXgTJzVAcq
    
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
