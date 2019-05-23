#pragma once
#include <sanitize_info.h>

namespace sanitize
{
    
struct parse_data_t
  {
  std::string app_tag, //logcat application tag
         so_path, //library file name path
         so_name; //library name
  std::size_t source_context_lines;
  };
  
  sanitizer_data_list_t parse( std::istream & input, parse_data_t options );
}

