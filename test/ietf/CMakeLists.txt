# Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE.
SET(TEST_PREFIX "ietf")
ENABLE_TESTING()

INCLUDE_DIRECTORIES( ../../src/liblsquic )

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLSQUIC_TEST=1")

IF (MSVC)
    SET(ADDL_SOURCES ../../wincompat/getopt.c ../../wincompat/getopt1.c)
    SET(LIB_FLAGS "-FORCE:MULTIPLE")
ELSE()
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-value")
    IF (CMAKE_C_COMPILER MATCHES gcc)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-override-init")
    ENDIF()
    IF (CMAKE_C_COMPILER MATCHES clang)
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-initializer-overrides")
    ENDIF()
ENDIF()

FOREACH(TEST_NAME parse varint crypto_gen hcsi_reader ack h3_prio)
    ADD_EXECUTABLE(test_${TEST_NAME} test_${TEST_NAME}.c)
    TARGET_LINK_LIBRARIES(test_${TEST_NAME} ${LIBS})
    ADD_TEST(${TEST_PREFIX}-${TEST_NAME} test_${TEST_NAME})
ENDFOREACH()
