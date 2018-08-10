echo "Connecting to 10.5.202.189"
$Server="10.5.202.189"
$User="USON\a-ej54mjh"
$Password="Sh168349#"
cmdkey /generic:TERMSRV/$Server /user:$User /pass:$Password
mstsc /v:$Server