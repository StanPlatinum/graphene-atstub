cd .
export GRAPHENE_DIR=$PWD
cd $GRAPHENE_DIR/Pal/src/host/Linux-SGX
make clean
cd ../../../..
make clean
