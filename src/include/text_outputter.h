#pragma once
#include <logcat_parser.h>

namespace sanitize::text_output
  {
  void process( sanitizer_data_list_t const & bugs, std::ostream & output );
  }

