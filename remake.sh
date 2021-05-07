cd .
export GRAPHENE_DIR=$PWD
export ISGX_DRIVER_PATH=/home/boxlinux-sgx-driver
cd $GRAPHENE_DIR
make SGX=1
