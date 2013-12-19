
cmake_minimum_required( VERSION 2.8 )
project( CDAX_SEC_CPP )

set( CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake" )

# update definitions and flags

set( CMAKE_CXX_FLAGS "-Wall -pedantic -Wno-unused-variable ${CMAKE_CXX_FLAGS}" )
add_definitions(
    -std=c++11
)

# boost and cryptopp

find_package( Boost COMPONENTS system thread serialization REQUIRED )
find_package( PCSCLite REQUIRED )
find_package( CryptoPP REQUIRED )

include_directories( SYSTEM ${Boost_INCLUDE_DIR} ${PCSCLITE_INCLUDE_DIR} ${CRYPTOPP_INCLUDE_DIRS} )

# Update libs
set( LIBS ${LIBS} ${Boost_LIBRARIES} ${PCSCLITE_LIBRARY} ${CRYPTOPP_LIBRARIES} )


add_executable( test CardTest
    card/SmartCard
    shared/Message
    shared/Common
)
target_link_libraries( test ${LIBS} )

# add_executable( simulator Main
#     clients/Subscriber
#     clients/Publisher
#     clients/Client
#     card/SmartCard
#     servers/SecurityServer
#     servers/Node
#     shared/Host
#     shared/Message
#     shared/Common
# )
# target_link_libraries( simulator ${LIBS} )

add_executable( msg_test Test
    card/SmartCard
    shared/Message
    shared/Common
)
target_link_libraries( msg_test ${LIBS} )
