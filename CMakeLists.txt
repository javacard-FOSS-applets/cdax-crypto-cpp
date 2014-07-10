
cmake_minimum_required( VERSION 2.8 )
project( CDAX_SEC_CPP )

set( CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake" )

# update definitions and flags

set( CMAKE_CXX_FLAGS "-std=c++0x -Wall -fpermissive -Wno-unused-variable ${CMAKE_CXX_FLAGS}" )

# boost and cryptopp
find_package( Boost COMPONENTS system thread serialization REQUIRED )
find_package( PCSCLite REQUIRED )
find_package( CryptoPP REQUIRED )

include_directories( SYSTEM ${Boost_INCLUDE_DIR} ${PCSCLITE_INCLUDE_DIR} ${CRYPTOPP_INCLUDE_DIRS} )

# Update libs
set( LIBS ${LIBS} ${Boost_LIBRARIES} ${PCSCLITE_LIBRARY} ${CRYPTOPP_LIBRARIES} )

add_executable( card_test CardTest
    card/SmartCard
    shared/Message
    shared/bytestring
    shared/TopicKeyPair
    shared/RSAKeyPair
    shared/Common
)
target_link_libraries( card_test ${LIBS} )

add_executable( simulator Main
    clients/Subscriber
    clients/Publisher
    clients/CardPublisher
    clients/CardSubscriber
    clients/Client
    clients/CardClient
    card/SmartCard
    servers/SecurityServer
    servers/Node
    shared/Host
    shared/Message
    shared/bytestring
    shared/TopicKeyPair
    shared/RSAKeyPair
    shared/Common
)
target_link_libraries( simulator ${LIBS} )

add_executable( msg_test MessageTest
    card/SmartCard
    shared/Message
    shared/bytestring
    shared/TopicKeyPair
    shared/RSAKeyPair
    shared/Common
)
target_link_libraries( msg_test ${LIBS} )

add_executable( msg_benchmark MessageBenchmark
    shared/Message
    shared/bytestring
    shared/TopicKeyPair
    shared/RSAKeyPair
    shared/Common
)
target_link_libraries( msg_benchmark ${LIBS} )

add_executable( benchmark_test BenchmarkTest
    shared/Message
    shared/bytestring
    shared/TopicKeyPair
    shared/RSAKeyPair
    shared/Common
)
target_link_libraries( benchmark_test ${LIBS} )

