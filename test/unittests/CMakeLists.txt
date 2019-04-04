# Copyright (c) 2017 - 2019 LiteSpeed Technologies Inc.  See LICENSE.
INCLUDE_DIRECTORIES(../../src/liblsquic)

ENABLE_TESTING()

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DLSQUIC_TEST=1")

IF (MSVC)
    SET(ADDL_SOURCES ../../wincompat/getopt.c ../../wincompat/getopt1.c)
    SET(LIB_FLAGS "-FORCE:MULTIPLE")
ELSE()
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-value")
    IF (CMAKE_C_COMPILER_ID STREQUAL GNU)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-override-init")
    ENDIF()
    IF (CMAKE_C_COMPILER_ID STREQUAL Clang)
        SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-initializer-overrides")
    ENDIF()
ENDIF()

SET(TESTS
    ackgen_gquic_be
    ackgen_gquic_le
    ackparse_gquic_be
    ackparse_gquic_le
    alarmset
    arr
    attq
    blocked_gquic_be
    blocked_gquic_le
    buf
    conn_close_gquic_be
    conn_close_gquic_le
    cubic
    dec
    di_nocopy
    elision
    engine_ctor
    export_key
    frame_chop
    frame_reader
    frame_writer
    goaway_gquic_be
    goaway_gquic_le
    h3_framing
    hkdf
    lsquic_hash
    malo
    packet_out
    packno_len
    parse_packet_in
    quic_be_floats
    quic_le_floats
    rechist
    reg_pkt_headergen
    rst_stream_gquic_be
    rst_stream_gquic_le
    rtt
    senhist
    set
    sfcw
    spi
    stop_waiting_gquic_be
    stop_waiting_gquic_le
    streamgen
    streamparse
    ver_nego
    wuf_gquic_be
    wuf_gquic_le
)

IF (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # Linux has fmemopen
    SET(TESTS ${TESTS} frame_rw)
ENDIF()


FOREACH(TEST_NAME ${TESTS})
    ADD_EXECUTABLE(test_${TEST_NAME} test_${TEST_NAME}.c ${ADDL_SOURCES})
    TARGET_LINK_LIBRARIES(test_${TEST_NAME} ${LIBS} ${LIB_FLAGS})
    ADD_TEST(${TEST_NAME} test_${TEST_NAME})
ENDFOREACH()

ADD_EXECUTABLE(test_stream test_stream.c ${ADDL_SOURCES})
TARGET_LINK_LIBRARIES(test_stream ${LIBS} ${LIB_FLAGS})
ADD_TEST(stream test_stream)
ADD_TEST(stream_hash test_stream -h)
ADD_TEST(stream_A test_stream -A)
ADD_TEST(stream_hash_A test_stream -A -h)

ADD_EXECUTABLE(graph_cubic graph_cubic.c ${ADDL_SOURCES})
TARGET_LINK_LIBRARIES(graph_cubic ${LIBS})

