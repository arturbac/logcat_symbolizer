#include <iostream>
#include <sanitize_info.h>
#include <logcat_parser.h>
#include <text_outputter.h>
#include <retext_outputter.h>

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/filesystem.hpp>

#include <sstream>

namespace po = boost::program_options;
namespace fs = boost::filesystem;
namespace sys = boost::system;


using std::string;
using std::exception;
using std::cout;
using std::endl;
using std::vector;

static constexpr const size_t source_context_lines_default { 8 };
static constexpr const char app_tag_default[] = " I wrap.sh :";
static constexpr const char library_path[] { "aAM-libs/asan_dev/arm64-v8a/libautomapa.e063.so" };
// static constexpr const char so_name[]{ "libautomapa.e063.so" };
// static constexpr const size_t so_name_size{ sizeof(so_name)/sizeof(char) };


using namespace sanitize;


int main ( int argc, char** argv ) 
  {
  string log_path, output_file, retext_directory;
  
  parse_data_t opt;
  po::options_description desc(
    "logcat sanitizer output stack trace symbolizer.\n"
    "\nAllowed arguments");
  desc.add_options()
    ("help,h", "Produce this help message.")
    ("log,l", po::value<std::string>(&log_path )->default_value("log.txt"), "path to logcat output log")
    ("output,o", po::value<std::string>(&output_file ), "If specified output will be redirected to file")
    ("retext,r", po::value<std::string>(&retext_directory ), "If specified produces retext output in specified subfolder")
    ("context,c",po::value<size_t>(&opt.source_context_lines)->default_value(source_context_lines_default),"attach to output N number of source file context")
    ("app_tag,t", po::value<std::string>(&opt.app_tag )->default_value(app_tag_default), "application tag phrase \" I MY_APP_TAG:\"")
    ("library_path,s", po::value<std::string>(&opt.so_path )->default_value(library_path), "path to library so with debug symbols")
    ;
    
  po::positional_options_description p;
  p.add("log", 1);
  po::variables_map vm;
  
  try
    {
    po::store( po::command_line_parser(argc, argv).options(desc).positional(p).run(), vm);
    po::notify(vm);
    } 
  catch (exception &e)
    {
    cout << endl << e.what() << endl;
    cout << desc << endl;
    return EXIT_FAILURE;
    }
  if (vm.count("help") || argc == 1)
    {
    cout << desc << endl;
    return EXIT_SUCCESS;
    }
  fs::path log_path_p{ log_path };
  if( !fs::exists( log_path_p ))
    {
    cout << "File " << log_path << " doesn't exists" << endl;
    return EXIT_FAILURE;
    }
  std::fstream input(log_path, input.in );
  
  if (!input.is_open()) 
    {
    std::cout << "failed to open " << log_path << endl;
    return EXIT_FAILURE;
    }
  
  //prepare so name to search
    {
    fs::path lib_name { opt.so_path };
    opt.so_name = lib_name.filename().string() + '+';
    }
  
  sanitizer_data_list_t bugs { parse( input, opt ) };
  std::sort( std::begin(bugs), std::end(bugs),
             [](sanitizer_data_t const & l, sanitizer_data_t const & r)
             {
             if( l.file_name != r.file_name )
               return l.file_name < r.file_name;
             return l.lineno < r.lineno;
             }
           );
  if( !retext_directory.empty() )
    {
    sanitize::retext_output::process(bugs, retext_directory);
    }
  else if( !output_file.empty() )
    {
    std::fstream output(output_file, output.out | output.trunc );
    sanitize::text_output::process( bugs, output );
    }
  else
    sanitize::text_output::process( bugs, cout );
  
  return EXIT_SUCCESS;
  }
