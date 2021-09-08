sudo sysctl vm.mmap_min_addr=0

cd .
export GRAPHENE_DIR=$PWD

cd $GRAPHENE_DIR/LibOS/shim/test/regression
make SGX=1 sgx-tokens
make
SGX=1 ./pal_loader helloworld

