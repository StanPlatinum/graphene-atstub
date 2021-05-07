cd .
export GRAPHENE_DIR=$PWD

cd $GRAPHENE_DIR/Pal/src/host/Linux-SGX/signer
openssl genrsa -3 -out enclave-key.pem 3072

export ISGX_DRIVER_PATH=/usr/local/src/sgx/linux-sgx-driver/
cd $GRAPHENE_DIR
make SGX=1
sudo sysctl vm.mmap_min_addr=0