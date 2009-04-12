#!/bin/csh

set PROG = prog
set KEYS = "secp112r1 secp112r2 secp128r1 secp128r2 secp160r1 secp160r2 secp192r1 secp224r1 secp256r1 secp384r1 secp521r1"

echo "RUNNING TESTS"
########################
# Test generating key
########################
foreach KEY ( $KEYS )
echo "######### ${KEY} #################"
	./${PROG} -g -c ${KEY} -okeys/${KEY}.pem
#	ls -l keys/${KEY}.pem

	if( $? == 0 ) then
		echo ${KEY} generated ok
	else
		echo Gen key ${KEY} failed
		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
		exit
	endif
end

########################
# Test exporting key
########################
echo "##################################"
echo "Exporting public Keys"
echo "##################################"

foreach KEY ( $KEYS )
echo "######### ${KEY} #################"
	./${PROG} -x -kkeys/${KEY}.pem -okeys/public_${KEY}.pem
	if( $? == 0 ) then
		echo ${KEY} key exported ok
	else
		echo Key export ${KEY} failed
		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
		exit
	endif
end

########################
# Test singing message
########################
foreach KEY ( $KEYS )
	echo "######### ${KEY} signing the message  #################"
	./${PROG} -s -kkeys/${KEY}.pem -omessage.txt.sign message.txt
	if( $? == 0 ) then
		echo Message signed ok
	else
		echo Message signed failed
		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
		exit
	endif

	echo "######### ${KEY} verifying the message  #################"
	./${PROG} -v -kkeys/public_${KEY}.pem -imessage.txt.sign message.txt
	if( $? == 0 ) then
		echo Message signed ok
	else
		echo Message signed failed
		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
		exit
	endif

		echo "######### ${KEY} verifying the message_changed  #################"
	./${PROG} -v -kkeys/public_${KEY}.pem -imessage.txt.sign message_changed.txt
	if( $? == 0 ) then
		echo Message signature ok - test failed
		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
		exit
	else
		echo Singature is not valid - test ok
	endif
end


foreach KEY ( $KEYS )
	echo "######### ${KEY} encrypting data  #################"
	./${PROG} -e -kkeys/public_${KEY}.pem message.txt
	if( $? == 0 ) then
		echo Message encrypted ok
	else
		echo Message encrypt failed
		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
		exit
	endif
	
	echo "######### ${KEY} decrypting data  #################"
	./${PROG} -d -kkeys/${KEY}.pem message.txt.enc
	if( $? == 0 ) then
		echo Message decrypted ok
	else
		echo Message decrypt failed
		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
		exit
	endif

	diff message.txt.orign message.txt
	if( $? != 0 ) then
		echo Message decrypted file is different
		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
		exit
	endif

	./${PROG} -d -kkeys/${KEY}.pem -omessage.txt.decrypted message.txt.enc
	if( $? == 0 ) then
		echo Message decrypted ok
	else
		echo Message dncrypt failed
		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
		exit
	endif
	
	diff message.txt.orign message.txt.decrypted
	if( $? != 0 ) then
		echo Message decrypted file is different
		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
		exit
	endif
end

echo "ALL TESTS PASSED"






