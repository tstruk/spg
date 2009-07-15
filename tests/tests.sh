#!/bin/csh

set PROG = spg
set KEYS = "secp112r1 secp128r1 secp160r1 secp160r2 secp192r1 secp224r1 secp256r1 secp384r1 secp521r1"

echo "RUNNING TESTS"
########################
# Test generating key
########################
#foreach KEY ( $KEYS )
#echo "######### ${KEY} #################"
#	./${PROG} -t -g -c ${KEY} -okeys/${KEY}.pem
##	ls -l keys/${KEY}.pem
#
#	if( $? == 0 ) then
#		echo ${KEY} generated ok
#	else
#		echo Gen key ${KEY} failed
#		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
#		exit
#	endif
#end

########################
# Test exporting key
########################
#echo "##################################"
#echo "Exporting public Keys"
#echo "##################################"

#foreach KEY ( $KEYS )
#echo "######### ${KEY} #################"
#	./${PROG} -t -x -kkeys/${KEY}.pem -okeys/public_${KEY}.pem
#	if( $? == 0 ) then
#		echo ${KEY} key exported ok
#	else
#		echo Key export ${KEY} failed
#		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
#		exit
#	endif
#end

########################
# Test singing message
########################
foreach KEY ( $KEYS )
	echo "######### ${KEY} signing the message  #################"
	./${PROG} -t -s -kkeys/${KEY}.pem -omessage.txt.sign message.txt
	if( $? == 0 ) then
		echo Message signed ok
	else
		echo Message signed failed
		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
		exit
	endif

	echo "######### ${KEY} verifying the message  #################"
	./${PROG} -t -v -kkeys/public_${KEY}.pem -imessage.txt.sign message.txt
	if( $? == 0 ) then
		echo Message signed ok
	else
		echo Message signed failed
		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
		exit
	endif

		echo "######### ${KEY} verifying the message_changed  #################"
	./${PROG} -t -v -kkeys/public_${KEY}.pem -imessage.txt.sign message_changed.txt
	if( $? == 0 ) then
		echo Message signature ok - test failed
		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
		exit
	else
		echo Singature is not valid - test ok
	endif
end

########################
# Test encrypt/decrypt
########################
foreach KEY ( $KEYS )
	echo "######### ${KEY} encrypting data  #################"
	./${PROG} -t -e -kkeys/public_${KEY}.pem message.txt
	if( $? == 0 ) then
		echo Message encrypted ok
	else
		echo Message encrypt failed
		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
		exit
	endif
	
	echo "######### ${KEY} decrypting data  #################"
	./${PROG} -t -d -kkeys/${KEY}.pem -o message.txt.dec message.txt.enc
	if( $? == 0 ) then
		echo Message decrypted ok
	else
		echo Message decrypt failed
		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
		exit
	endif

	diff message_orign.txt message.txt.dec
	if( $? != 0 ) then
		echo Message decrypted file is different
		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
		exit
	endif

	./${PROG} -t -d -kkeys/${KEY}.pem -omessage.txt.decrypted message.txt.enc
	if( $? == 0 ) then
		echo Message decrypted ok
	else
		echo Message dncrypt failed
		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
		exit
	endif
	
	diff message_orign.txt message.txt.decrypted
	if( $? != 0 ) then
		echo Message decrypted file is different
		echo "!!!!!!!!!!!!!! FAILED !!!!!!!!!!!!!!!"
		exit
	endif
end

echo "ALL TESTS PASSED"






