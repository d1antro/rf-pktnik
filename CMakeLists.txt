cmake_minimum_required(VERSION 3.21)
project(RFTrafficEditor LANGUAGES CXX)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "pktnik is 32-bit only. Configure with:  cmake -S . -B build -A Win32 ...")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

find_package(minhook CONFIG REQUIRED)
find_package(imgui CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(unofficial-lua-cpp CONFIG REQUIRED)

file(GLOB_RECURSE SRC CONFIGURE_DEPENDS src/*.cpp)

add_library(RFTrafficEditor SHARED ${SRC})
target_include_directories(RFTrafficEditor PRIVATE src)
target_compile_definitions(RFTrafficEditor PRIVATE
  WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS UNICODE _UNICODE)
target_link_libraries(RFTrafficEditor PRIVATE
  minhook::minhook
  imgui::imgui
  nlohmann_json::nlohmann_json
  lua-cpp
  d3d11 dxgi d3dcompiler dwmapi imm32)

set_target_properties(RFTrafficEditor PROPERTIES OUTPUT_NAME "RFTrafficEditor")

add_custom_target(RFTrafficEditor_data ALL
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${CMAKE_SOURCE_DIR}/data/packet_db.json" "$<TARGET_FILE_DIR:RFTrafficEditor>/packet_db.json"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${CMAKE_SOURCE_DIR}/data/RFTrafficEditor.rules.example.json"
          "$<TARGET_FILE_DIR:RFTrafficEditor>/RFTrafficEditor.rules.example.json"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${CMAKE_SOURCE_DIR}/data/RFTrafficEditor.example.lua"
          "$<TARGET_FILE_DIR:RFTrafficEditor>/RFTrafficEditor.example.lua"
  VERBATIM)
add_dependencies(RFTrafficEditor_data RFTrafficEditor)

enable_testing()
set(RFTE_2232_BIN "not-set"
    CACHE FILEPATH "2232 client image: the 2232 row's signatures are verified against it (and the 4.15 / 4.55 / EP1P2 rows must not verify)")
set(RFTE_415_BIN "not-set"
    CACHE FILEPATH "4.15 client image: the 4.15 row's signatures are verified against it (and the 2232 / 4.55 / EP1P2 rows must not verify)")
set(RFTE_455_BIN "not-set"
    CACHE FILEPATH "4.55 client image: the 4.55 row's signatures are verified against it (and the 2232 / 4.15 / EP1P2 rows must not verify)")
set(RFTE_EP1P2_BIN "not-set"
    CACHE FILEPATH "EP1P2 client image (a pe-sieve dump of RF_classic.bin, raw == VA): the EP1P2 row's signatures are verified against it (and the 2232 / 4.15 / 4.55 rows must not verify)")
add_executable(test_signatures tests/test_signatures.cpp src/build/signature.cpp src/build/profiles.cpp)
target_include_directories(test_signatures PRIVATE src)
target_compile_definitions(test_signatures PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
add_test(NAME signatures COMMAND test_signatures "${RFTE_2232_BIN}" "${RFTE_415_BIN}" "${RFTE_455_BIN}" "${RFTE_EP1P2_BIN}")

add_executable(test_chain tests/test_chain.cpp)
target_compile_definitions(test_chain PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
target_link_libraries(test_chain PRIVATE minhook::minhook)
add_test(NAME chain COMMAND test_chain)

add_executable(test_capture tests/test_capture.cpp src/hooks/capture_ring.cpp src/proto/packet_text.cpp
                            src/proto/decode.cpp)
target_include_directories(test_capture PRIVATE src)
target_compile_definitions(test_capture PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
add_test(NAME capture COMMAND test_capture)

add_executable(test_actions tests/test_actions.cpp src/hooks/action_queue.cpp src/proto/packet_text.cpp
                            src/proto/decode.cpp)
target_include_directories(test_actions PRIVATE src)
target_compile_definitions(test_actions PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
add_test(NAME actions COMMAND test_actions)

add_executable(test_script tests/test_script.cpp src/script/script_host.cpp src/ui/field_edit.cpp
                           src/proto/packet_db.cpp src/proto/decode.cpp src/proto/packet_text.cpp
                           src/hooks/patch_rules.cpp src/hooks/rules_file.cpp)
target_include_directories(test_script PRIVATE src)
target_compile_definitions(test_script PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
target_link_libraries(test_script PRIVATE lua-cpp nlohmann_json::nlohmann_json)
add_test(NAME script COMMAND test_script "${CMAKE_SOURCE_DIR}/data/RFTrafficEditor.example.lua"
                                         "${CMAKE_SOURCE_DIR}/data/packet_db.json"
                                         )
set_tests_properties(script PROPERTIES TIMEOUT 120)

add_executable(test_rules tests/test_rules.cpp src/hooks/patch_rules.cpp src/hooks/rules_file.cpp src/ui/rule_edit.cpp)
target_include_directories(test_rules PRIVATE src)
target_compile_definitions(test_rules PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
target_link_libraries(test_rules PRIVATE nlohmann_json::nlohmann_json)
add_test(NAME rules COMMAND test_rules "${CMAKE_SOURCE_DIR}/data/RFTrafficEditor.rules.example.json")

add_executable(test_decode tests/test_decode.cpp src/proto/packet_db.cpp src/proto/decode.cpp src/proto/packet_text.cpp)
target_include_directories(test_decode PRIVATE src)
target_compile_definitions(test_decode PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
target_link_libraries(test_decode PRIVATE nlohmann_json::nlohmann_json)
add_test(NAME decode COMMAND test_decode "${CMAKE_SOURCE_DIR}/data/packet_db.json"
                                         "${CMAKE_SOURCE_DIR}/tests/fixtures/packet_db_mini.json")

add_executable(test_model tests/test_model.cpp src/ui/packet_model.cpp src/ui/packet_view.cpp src/ui/filter.cpp src/ui/field_edit.cpp src/proto/packet_db.cpp
                          src/proto/decode.cpp src/proto/packet_text.cpp)
target_include_directories(test_model PRIVATE src)
target_compile_definitions(test_model PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
target_link_libraries(test_model PRIVATE nlohmann_json::nlohmann_json)
add_test(NAME model COMMAND test_model "${CMAKE_SOURCE_DIR}/data/packet_db.json"
                                       "${CMAKE_SOURCE_DIR}/tests/fixtures/packet_db_mini.json")

add_executable(test_ui tests/test_ui.cpp src/ui/ui.cpp src/ui/packet_model.cpp src/ui/packet_view.cpp src/ui/filter.cpp src/ui/field_edit.cpp src/proto/packet_db.cpp
                       src/proto/decode.cpp src/proto/packet_text.cpp src/util/log.cpp
                       src/hooks/patch_rules.cpp src/hooks/rules_file.cpp src/ui/rule_edit.cpp
                       src/script/script_host.cpp)
target_include_directories(test_ui PRIVATE src)
target_compile_definitions(test_ui PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS UNICODE _UNICODE)
target_link_libraries(test_ui PRIVATE imgui::imgui nlohmann_json::nlohmann_json lua-cpp d3d11 dxgi d3dcompiler dwmapi imm32)
add_test(NAME ui COMMAND test_ui "${CMAKE_SOURCE_DIR}/data/packet_db.json")
set_tests_properties(ui PROPERTIES TIMEOUT 90)
