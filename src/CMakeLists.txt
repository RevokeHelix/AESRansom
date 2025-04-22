cmake_minimum_required(VERSION 3.10)
project(Dropper)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(RESOURCE_RC ${CMAKE_CURRENT_SOURCE_DIR}/resources.rc)
set(RESOURCE_RES ${CMAKE_CURRENT_BINARY_DIR}/resources.res)

# Compile .rc to .res
if (MSVC)
    add_custom_command(
        OUTPUT ${RESOURCE_RES}
        COMMAND rc /nologo /fo ${RESOURCE_RES} ${RESOURCE_RC}
        DEPENDS ${RESOURCE_RC}
        COMMENT "Compiling resources.rc with MSVC RC"
    )
else()
    find_program(WINDRES windres REQUIRED)
    add_custom_command(
        OUTPUT ${RESOURCE_RES}
        COMMAND ${WINDRES} ${RESOURCE_RC} -O coff -o ${RESOURCE_RES}
        DEPENDS ${RESOURCE_RC}
        COMMENT "Compiling resources.rc with windres"
    )
endif()

# Ensure .res is treated as binary object
if (MSVC)
    set_source_files_properties(${RESOURCE_RES} PROPERTIES
        EXTERNAL_OBJECT TRUE
    )
endif()

# Create custom target for the resource
add_custom_target(ResourcesTarget ALL DEPENDS ${RESOURCE_RES})

# Build executable and embed .res
add_executable(Dropper main.cpp ${RESOURCE_RES})
add_dependencies(Dropper ResourcesTarget)

# Ensure console subsystem
if (MSVC)
    target_link_options(Dropper PRIVATE /SUBSYSTEM:CONSOLE)
else()
    target_link_libraries(Dropper PRIVATE -mconsole)
endif()
