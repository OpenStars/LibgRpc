# Prepare and build
## Get Source codes 
``
 bash getsource.sh
``

## Build and install protobuf
cd third_party/protobuf 
``
./autogen
./configure
make
sudo make install
``

##build grpc lib 
``
cd sources/grpc
make 
``
