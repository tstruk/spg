#!/bin/csh

set PROG = spg
set KEYS = "secp112r1 secp128r1 secp160r1 secp160r2 secp192r1 secp224r1 secp256r1 secp384r1 secp521r1"

rm -f keys/*

echo "RUNNING TESTS"
########################
# Test generating key
########################
foreach KEY ($KEYS)
echo "######### ${KEY} #################"
	echo ./${PROG} -g -c ${KEY} -okeys/${KEY}.pem
	./${PROG} -g -c ${KEY} -okeys/${KEY}.pem
	ls -l keys/${KEY}.pem

	if($? == 0) then
		echo ${KEY} generated ok
	else
		echo Gen key ${KEY} failed
		echo "Test Failed!"
		exit
	endif
end

########################
# Test exporting key
########################
echo "##################################"
echo "Exporting public Keys"
echo "##################################"

foreach KEY ($KEYS)
echo "######### ${KEY} #################"
	echo ./${PROG} -x -kkeys/${KEY}.pem -okeys/public_${KEY}.pem
	./${PROG} -x -kkeys/${KEY}.pem -okeys/public_${KEY}.pem
	if($? == 0) then
		echo ${KEY} key exported ok
	else
		echo Key export ${KEY} failed
		echo "Test Failed!"
		exit
	endif
end

########################
# Test singing message
########################
foreach KEY ($KEYS)
	echo "######### ${KEY} signing the message  #################"
	echo ./${PROG} -s -kkeys/${KEY}.pem -omessage.txt.sign message.txt
	./${PROG} -s -kkeys/${KEY}.pem -omessage.txt.sign message.txt
	if($? == 0) then
		echo Message signed ok
	else
		echo Message signed failed
		echo "Test Failed!"
		exit
	endif

	echo "######### ${KEY} verifying the message  #################"
	echo ./${PROG} -v -kkeys/public_${KEY}.pem -imessage.txt.sign message.txt
	./${PROG} -v -kkeys/public_${KEY}.pem -imessage.txt.sign message.txt
	if($? == 0) then
		echo Message signed ok
	else
		echo Message signed failed
		echo "Test Failed!"
		exit
	endif

		echo "######### ${KEY} verifying the message_changed  #################"
	echo ./${PROG} -v -kkeys/public_${KEY}.pem -imessage.txt.sign message_changed.txt
	./${PROG} -v -kkeys/public_${KEY}.pem -imessage.txt.sign message_changed.txt
	if($? == 0) then
		echo Message signature ok - test failed
		echo "Test Failed!"
		exit
	else
		echo Singature is not valid - test ok
	endif
end

########################
# Test encrypt/decrypt
########################
foreach KEY ($KEYS)
	echo "######### ${KEY} encrypting data  #################"
	echo ./${PROG} -e -kkeys/public_${KEY}.pem message.txt
	./${PROG} -e -kkeys/public_${KEY}.pem message.txt
	if($? == 0) then
		echo Message encrypted ok
	else
		echo Message encrypt failed
		echo "Test Failed!"
		exit
	endif

	echo "######### ${KEY} decrypting data  #################"
	echo ./${PROG} -d -kkeys/${KEY}.pem -o message.txt.dec message.txt.enc
	./${PROG} -d -kkeys/${KEY}.pem -o message.txt.dec message.txt.enc
	if($? == 0) then
		echo Message decrypted ok
	else
		echo Message decrypt failed
		echo "Test Failed!"
		exit
	endif

	diff message_orign.txt message.txt.dec
	if($? != 0) then
		echo Message decrypted file is different
		echo "Test Failed!"
		exit
	endif

	echo ./${PROG} -d -kkeys/${KEY}.pem -omessage.txt.decrypted message.txt.enc
	./${PROG} -d -kkeys/${KEY}.pem -omessage.txt.decrypted message.txt.enc
	if($? == 0) then
		echo Message decrypted ok
	else
		echo Message dncrypt failed
		echo "Test Failed!"
		exit
	endif

	diff message_orign.txt message.txt.decrypted
	if($? != 0) then
		echo Message decrypted file is different
		echo "Test Failed!"
		exit -1
	endif
end
echo "ALL TESTS PASSED"
