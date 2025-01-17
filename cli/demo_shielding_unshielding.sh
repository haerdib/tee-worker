#!/bin/bash

# setup:
# run all on localhost:
#   integritee-node purge-chain --dev
#   integritee-node --dev -lruntime=debug
#   rm light_client_db.bin
#   export RUST_LOG=integritee_service=info,ita_stf=debug
#   integritee-service init_shard
#   integritee-service shielding-key
#   integritee-service signing-key
#   integritee-service run
#
# then run this script

# usage:
#  demo_shielding_unshielding.sh -p <NODEPORT> -P <WORKERPORT> -t <TEST_BALANCE_RUN> -m file
#
# TEST_BALANCE_RUN is either "first" or "second"
# if -m file is set, the mrenclave will be read from file

while getopts ":m:p:P:t:u:V:C:" opt; do
    case $opt in
        t)
            TEST=$OPTARG
            ;;
        m)
            READMRENCLAVE=$OPTARG
            ;;
        p)
            NPORT=$OPTARG
            ;;
        P)
            WORKER1PORT=$OPTARG
            ;;
        u)
            NODEURL=$OPTARG
            ;;
        V)
            WORKER1URL=$OPTARG
            ;;
        C)
            CLIENT_BIN=$OPTARG
            ;;
    esac
done

# Using default port if none given as arguments.
NPORT=${NPORT:-9944}
NODEURL=${NODEURL:-"ws://127.0.0.1"}

WORKER1PORT=${WORKER1PORT:-2000}
WORKER1URL=${WORKER1URL:-"wss://127.0.0.1"}

CLIENT_BIN=${CLIENT_BIN:-"./../bin/integritee-cli"}

echo "Using client binary ${CLIENT_BIN}"
echo "Using node uri ${NODEURL}:${NPORT}"
echo "Using trusted-worker uri ${WORKER1URL}:${WORKER1PORT}"
echo ""

AMOUNTSHIELD=50000000000
AMOUNTTRANSFER=25000000000
AMOUNTUNSHIELD=15000000000

CLIENT="${CLIENT_BIN} -p ${NPORT} -P ${WORKER1PORT} -u ${NODEURL} -U ${WORKER1URL}"

echo "* Query on-chain enclave registry:"
${CLIENT} list-workers
echo ""

if [ "$READMRENCLAVE" = "file" ]
then
    read MRENCLAVE <<< $(cat ~/mrenclave.b58)
    echo "Reading MRENCLAVE from file: ${MRENCLAVE}"
else
    # this will always take the first MRENCLAVE found in the registry !!
    read MRENCLAVE <<< $($CLIENT list-workers | awk '/  MRENCLAVE: / { print $2; exit }')
    echo "Reading MRENCLAVE from worker list: ${MRENCLAVE}"
fi
[[ -z $MRENCLAVE ]] && { echo "MRENCLAVE is empty. cannot continue" ; exit 1; }

echo "* Get balance of Alice's on-chain account"
${CLIENT} balance "//Alice"
echo ""

echo "* Get balance of Bob's on-chain account"
${CLIENT} balance "//Bob"
echo ""

echo "* Create a new incognito account for Alice"
#ICGACCOUNTALICE=$(${CLIENT} trusted new-account --mrenclave ${MRENCLAVE})
ICGACCOUNTALICE=//AliceIncognito
echo "  Alice's incognito account = ${ICGACCOUNTALICE}"
echo ""

echo "* Create a new incognito account for Bob"
ICGACCOUNTBOB=$(${CLIENT} trusted --mrenclave ${MRENCLAVE} new-account )
echo "  Bob's incognito account = ${ICGACCOUNTBOB}"
echo ""

# Sometimes we get a nonce clash here, so let's wait a little bit to prevent that.
sleep 10

echo "* Shield ${AMOUNTSHIELD} tokens to Alice's incognito account"
${CLIENT} shield-funds //Alice ${ICGACCOUNTALICE} ${AMOUNTSHIELD} ${MRENCLAVE}
echo ""

echo "* Waiting 30 seconds"
sleep 30
echo ""

echo "Get balance of Alice's incognito account"
${CLIENT} trusted --mrenclave ${MRENCLAVE} balance ${ICGACCOUNTALICE}
echo ""

echo "* Get balance of Alice's on-chain account"
${CLIENT} balance "//Alice"
echo ""

echo "* Send ${AMOUNTTRANSFER} funds from Alice's incognito account to Bob's incognito account"
$CLIENT trusted --mrenclave ${MRENCLAVE} transfer ${ICGACCOUNTALICE} ${ICGACCOUNTBOB} ${AMOUNTTRANSFER}
echo ""

echo "* Get balance of Alice's incognito account"
${CLIENT} trusted --mrenclave ${MRENCLAVE} balance ${ICGACCOUNTALICE}
echo ""

echo "* Bob's incognito account balance"
${CLIENT} trusted --mrenclave ${MRENCLAVE} balance ${ICGACCOUNTBOB}
echo ""

echo "* Un-shield ${AMOUNTUNSHIELD} tokens from Alice's incognito account"
${CLIENT} trusted --mrenclave ${MRENCLAVE} --xt-signer //Alice unshield-funds ${ICGACCOUNTALICE} //Alice ${AMOUNTUNSHIELD}
echo ""

echo "* Waiting 30 seconds"
sleep 30
echo ""

echo "Get balance of Alice's incognito account"
RESULT=$(${CLIENT} trusted --mrenclave ${MRENCLAVE} balance ${ICGACCOUNTALICE}  | xargs)
echo $RESULT

echo "* Get balance of Alice's on-chain account"
${CLIENT} balance "//Alice"
echo ""


# The following tests are for automated CI.
# They only work if you're running from fresh genesis.
case $TEST in
    first)
        if [ "10000000000" = "$RESULT" ]; then
            echo "test passed (1st time)"
            exit 0
        else
            echo "test ran through but balance is wrong. have you run the script from fresh genesis?"
            exit 1
        fi
        ;;
    second)
        if [ "20000000000" = "$RESULT" ]; then
            echo "test passed (2nd time)"
            exit 0
        else
            echo "test ran through but balance is wrong. is this really the second time you run this since genesis?"
            exit 1
        fi
        ;;
esac

exit 0
