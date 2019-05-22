#include <iostream>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/filesystem.hpp>
#include <boost/process.hpp>
#include <sstream>
#include <string_view>

namespace po = boost::program_options;
namespace fs = boost::filesystem;
namespace sys = boost::system;
namespace process= boost::process;

using std::string;
using std::exception;
using std::cout;
using std::endl;
using std::string_view;

static constexpr const size_t source_context_lines_default { 8 };
static constexpr const char app_tag_default[] = " I wrap.sh:";
static constexpr const char library_path[] { "aAM-libs/asan_dev/arm64-v8a/libautomapa.e063.so" };
// static constexpr const char so_name[]{ "libautomapa.e063.so" };
// static constexpr const size_t so_name_size{ sizeof(so_name)/sizeof(char) };

struct parse_data_t
  {
  string app_tag, //logcat application tag
         so_path, //library file name path
         so_name; //library name
  size_t source_context_lines;
  };
  
static void parse( std::istream & input, std::ostream & output, parse_data_t options );

int main ( int argc, char** argv ) 
  {
  string log_path, output_file;
  
  parse_data_t opt;
  po::options_description desc(
    "logcat sanitizer output stack trace symbolizer.\n"
    "\nAllowed arguments");
  desc.add_options()
    ("help,h", "Produce this help message.")
    ("log,l", po::value<std::string>(&log_path )->default_value("log.txt"), "path to logcat output log")
    ("output,o", po::value<std::string>(&output_file ), "If specified output will be redirected to file")
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
  
  if( !output_file.empty() )
    {
    std::fstream output(output_file, output.out | output.trunc );
    parse( input, output, opt );
    }
  else
    parse( input, cout, opt );
  
  return EXIT_SUCCESS;
  }

static constexpr const char llvm_decl[] = "llvm-symbolizer -demangle -addresses -inlining -pretty-print -functions=short ";
static void parse( std::istream & input, std::ostream & output, parse_data_t options )
  {
    string llvm;
    {
    std::stringstream llvm_tmp;
    llvm_tmp << llvm_decl << " -e " << options.so_path << " -print-source-context-lines=" << options.source_context_lines;
    llvm = llvm_tmp.str();
    }
  string line;
  while(std::getline(input, line) )
    {
//05-22 16:03:03.219  7119  7119 I wrap.sh :     #0 0x5dbfa9362c  (/data/app/pl.aqurat.automapa.dev-hXbndcV7xWyVpqyxV4uHbA==/lib/arm64/libautomapa.e063.so+0x6bc762c)
    auto it { line.find( options.app_tag ) };
    if (it != string::npos )
      {
      it += options.app_tag.size();
      string log_text { line.substr( it ) };
      //if log line contains backtrace from libart skip it
      if( string::npos != log_text.find("libart.so") )
        continue;
      
      //if line contains runtime error: break it 
        {
        string_view rt_err { "runtime error:" };
        auto it_rterr { log_text.find(rt_err) };
        if( it_rterr == string::npos )
          output << log_text << endl;
        else
          output << log_text.substr( 0, it_rterr ) << endl 
                 << log_text.substr( it_rterr ) << endl;
        }
        
      if( string::npos != log_text.find("SUMMARY") )
        output << "\n======================================================================================================================================" << endl;
      //libautomapa.e063.so+0x4260b92)
      auto it_addr = log_text.find(options.so_name); //
      if( it_addr != string::npos )
        {
        it_addr += options.so_name.size();
        string address { log_text.substr( it_addr, log_text.size() - it_addr -1 ) };
//          output << "ADDRESS" << address << endl;
        std::stringstream llvm_args;
        llvm_args << llvm << " " << address;
        output << "//" << llvm_args.str() << endl;
   
        process::ipstream pipe_stream;
        auto pipe { process::std_out > pipe_stream };
        process::child c(llvm_args.str(), pipe );
        std::string child_line;
        while (pipe_stream && std::getline(pipe_stream, child_line) && !child_line.empty())
          output << child_line << endl;

        c.wait();
        pipe_stream.pipe().close();
        }
      }
    }
  }
