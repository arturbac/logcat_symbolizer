#include <text_outputter.h>
#include <iostream>
#include <algorithm>

namespace sanitize::text_output
{
  using std::begin;
  using std::end;
  using std::endl;
  
  void process( sanitizer_data_list_t const & bugs, std::ostream & output )
    {
    output 
        << "\n======================================================================================================================================" << endl
        << " Files affected in report :" << endl
        ;
    std::vector<std::string> file_names;
    
    std::transform( begin(bugs), end(bugs), std::back_inserter(file_names), [](sanitizer_data_t const & data ){ return data.file_name; } ); 
    auto it_new_end { std::unique( begin(file_names), end(file_names)) };
    file_names.erase(it_new_end, end(file_names) );
    std::sort( begin(file_names), end(file_names) );
    for( std::string_view file_name : file_names )
      output << file_name << endl;
    
    for( sanitizer_data_t const & data : bugs )
      {
      
      output 
        << "\n======================================================================================================================================" << endl
        << "Error :" << data.error_description << endl
        << "file " << data.file_name << " line " << data.lineno << endl
        << "Summary" << data.summary << endl
        << "llvm :" << data.llvm_args << endl
        << "bactrace : "<< endl << data.source_context << endl
        ;
      }
    }
  }


