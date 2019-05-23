set(CMAKE_BUILD_DIR ${PROJECT_SOURCE_DIR}/build)


if(EXISTS "${CMAKE_SOURCE_DIR}/.git")
  execute_process(
    COMMAND git rev-parse HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_BRANCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
else()
  set(GIT_BRANCH "Unknown")
endif()
add_definitions(-DGIT_BRANCH=${GIT_BRANCH})

add_executable(logcat_symbolizer )

target_include_directories( logcat_symbolizer
 PRIVATE
    include 
  )
  
target_sources(logcat_symbolizer
   PRIVATE
     main.cc
     logcat_parser.cc
     text_outputter.cc
     retext_outputter.cc
     )
     
target_link_libraries( logcat_symbolizer PRIVATE  
  Boost::program_options
  Boost::system
  Boost::filesystem
  Boost::thread 
  )

install(TARGETS logcat_symbolizer DESTINATION ${CMAKE_INSTALL_PREFIX}/bin)
