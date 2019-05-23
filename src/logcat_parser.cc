#include <logcat_parser.h>
#include <sstream>
#include <boost/process.hpp>
#include <iostream>

using std::string;
using std::string_view;

namespace process = boost::process;

namespace sanitize
{

static constexpr const char llvm_decl[] = "llvm-symbolizer -demangle -addresses -inlining -pretty-print -functions=short ";

sanitizer_data_list_t parse( std::istream & input, parse_data_t options )
  {
    string llvm;
    {
    std::stringstream llvm_tmp;
    llvm_tmp << llvm_decl << " -e " << options.so_path << " -print-source-context-lines=" << options.source_context_lines;
    llvm = llvm_tmp.str();
    }
  sanitizer_data_list_t bugs;
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
      
        {
        static constexpr string_view RUNTIME_ERROR{ "runtime error:" };
        if( auto it_rterr { log_text.find(RUNTIME_ERROR) }; it_rterr != string::npos )
          {
          //start new bug description
          sanitizer_data_t data;
          data.error_description = log_text.substr( it_rterr );
          std::cout << "Bug " << data.error_description << std::endl;
          while(std::getline(input, line) )
            {
            auto it2 { line.find( options.app_tag ) };
            if (it2 != string::npos )
              {
              it2 += options.app_tag.size();
              string log_text2 { line.substr( it2 ) };
              static constexpr string_view SUMMARY { "SUMMARY" };
              if( string::size_type it_summary = log_text2.find( SUMMARY ); string::npos != it_summary  )
                {
                //SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /md1/home/artur/projects/ameu_online_aam/Components/Include/android/../StringBase.h:85:22 in
                //bug is done
                it_summary += SUMMARY.size();
                data.summary = log_text2.substr( it_summary );
                auto it_last_slash{ data.summary.rfind('/') };
                auto it_header_end{ data.summary.find(':', it_last_slash )};
                auto it_lineno_end{ data.summary.find(':', it_header_end + 1 )};
                data.file_name =  data.summary.substr( it_last_slash + 1, it_header_end- it_last_slash - 1 );
                std::string lineno{ data.summary.substr( it_header_end + 1, it_lineno_end - it_header_end )};
                data.lineno = std::stoi( lineno );
                break;
                }
              //parse frame data
              //if log line contains backtrace from libart skip it
              if( string::npos != log_text2.find("libart.so") )
                continue;
              //parse frames
                {
                auto it_addr = log_text2.find(options.so_name);
                if( it_addr != string::npos )
                  {
                  it_addr += options.so_name.size();
                  string address { log_text2.substr( it_addr, log_text2.size() - it_addr -1 ) };
                  //std::cout << "ADDRESS" << address << endl;
                  data.frames.emplace_back( frame_t{ std::move(address) } ) ;
                  }
                }
              }
            }
          //finish bug data
            {
            //prepare llvm-smbolizer
            std::stringstream llvm_args;
            llvm_args << llvm ;
            std::for_each( std::begin(data.frames), std::end(data.frames), 
                           [&llvm_args]( frame_t const & frame)
                           { llvm_args << " " << frame.source_address_info; } 
                         );
            data.llvm_args = llvm_args.str();
            }
          //collect source context
            {
            process::ipstream pipe_stream;
            auto pipe { process::std_out > pipe_stream };
            process::child c( data.llvm_args, pipe );
            std::stringstream source_context;
            std::string child_line;
            while (pipe_stream && std::getline(pipe_stream, child_line) )
              {
              if( !child_line.empty() )
                source_context << child_line << std::endl;
              }

            c.wait();
            pipe_stream.pipe().close();
            data.source_context = source_context.str();
            }
          bugs.emplace_back( std::move( data ) );
          }
        }
#if 0
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
#endif
      }
    }
  return bugs;
  }

}
