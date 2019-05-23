#pragma once
#include <string>
#include <vector>

namespace sanitize
{
struct frame_t
  {
  std::string source_address_info;
  };
struct sanitizer_data_t
  {
  std::string
     error_description,
     file_name,
     summary,
     source_context,
     llvm_args;
 int lineno;
  
  std::vector<frame_t> frames;
  };
  
using sanitizer_data_list_t = std::vector<sanitizer_data_t>;

}
