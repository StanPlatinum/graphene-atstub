cd .
export GRAPHENE_DIR=$PWD
export ISGX_DRIVER_PATH=$OOT_DRIVER_DIR/linux-sgx-driver
#export ISGX_DRIVER_PATH=/usr/local/src/sgx/linux-sgx-driver
cd $GRAPHENE_DIR
make SGX=1
