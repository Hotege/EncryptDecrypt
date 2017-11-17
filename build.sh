BASE_DIR=`pwd`

rm build -rf
mkdir build

pushd build

cmake ..

make -j8

INSTALL_DIR=$BASE_DIR/encryptdecrypt_distribute
rm -rf $INSTALL_DIR
make install/strip DESTDIR=$INSTALL_DIR

popd

cp -r libabstractalgorithm encryptdecrypt_distribute
cp -r librandom encryptdecrypt_distribute

rm libencryptdecrypt -rf
mkdir libencryptdecrypt

pushd libencryptdecrypt

cp -r ../encryptdecrypt_distribute/include ./
cp -r ../encryptdecrypt_distribute/lib ./

popd