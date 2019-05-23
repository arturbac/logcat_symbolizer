#include <retext_outputter.h>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <boost/filesystem.hpp>

static constexpr std::string_view config_py
  {
R"(# Configuration file for the Sphinx documentation builder.
#
# This file only contains a selection of the most common options. For a full
# list see the documentation:
# http://www.sphinx-doc.org/en/master/config

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))


# -- Project information -----------------------------------------------------

project = 'asan_aAm_air'
copyright = '2019, log_cat_sanitizer'
author = 'log_cat_sanitizer'


# -- General configuration ---------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
]

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path.
exclude_patterns = []


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
#html_theme = 'alabaster'
extensions += ['sphinxjp.themes.basicstrap']
html_theme = 'basicstrap'

html_theme_options = {
  'body_max_width' : '4000px'
  }
# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ['_static']
)"
  };

static constexpr std::string_view index_rst_head
{
R"(
Welcome to asan_aAm_air's documentation!
========================================

.. toctree::
   :maxdepth: 2
   :caption: Contents:)" };

static constexpr std::string_view index_rst_footer
{
R"(
Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
  )"
};

static constexpr std::string_view makefile
{
R"code(
# Minimal makefile for Sphinx documentation
#

# You can set these variables from the command line.
SPHINXOPTS    =
SPHINXBUILD   = sphinx-build
SOURCEDIR     = source
BUILDDIR      = build

# Put it first so that "make" without argument is like "make help".
help:
	@$(SPHINXBUILD) -M help "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)

.PHONY: help Makefile

# Catch-all target: route all unknown targets to Sphinx using the new
# "make mode" option.  $(O) is meant as a shortcut for $(SPHINXOPTS).
%: Makefile
	@$(SPHINXBUILD) -M $@ "$(SOURCEDIR)" "$(BUILDDIR)" $(SPHINXOPTS) $(O)
)code"};


namespace sanitize::retext_output
{
  using std::begin;
  using std::end;
  using std::endl;
  using std::string;
  using std::fstream;
  
  namespace fs = boost::filesystem;
  namespace sys = boost::system;

  void process( sanitizer_data_list_t const & bugs, std::string const & output_path )
  try
    {
    fs::path path{ output_path };
    if( !fs::exists( path) )
      fs::create_directory( path );
    
    fs::path source { path};
    source.append("/source");
    if( !fs::exists( source ) )
      {
      fs::create_directory( source );
      }
      
    fs::path subsource { source };
    subsource.append("/source");
    if( !fs::exists( subsource ) )
      fs::create_directory( subsource );
      
      {
      fs::path out_makefile { path };
      out_makefile.append( "/Makefile");
      fstream main_output(out_makefile.string(), fstream::out | fstream::trunc );
      main_output << makefile << "\n";
      }
      {
      fs::path out_config { source };
      out_config.append( "/conf.py");
      fstream output(out_config.string(), fstream::out | fstream::trunc );
      output << config_py << "\n";
      }
    fs::path out_main_file { source };
    out_main_file.append( "/index.rst");
    fstream main_output(out_main_file.string(), fstream::out | fstream::trunc );
    main_output << index_rst_head << "\n\n";
    
    string previous_file;
    for( auto it{ begin(bugs) };  end(bugs) != it; )
      {
      //page for give file name
      if( previous_file != it->file_name )
        {
        previous_file = it->file_name;
      
        main_output << " source/" << previous_file << endl;
      
        fs::path out_file { subsource };
        out_file.append( "/" + string{previous_file} + ".rst");
        fstream output(out_file.string(), fstream::out | fstream::trunc );
        output << previous_file << endl << "=================================================================\n\n";
        //iterate over bugs for given file
        while( previous_file == it->file_name  )
          {
          sanitizer_data_t const & data { *it };
          output << data.file_name << " line " << data.lineno << endl 
          << "-----------------------------------------------------------------\n\n"
          << data.error_description << "\n\n"
          << "``" << data.llvm_args << "``\n\n"
          << ".. code-block::\n\n";
            {
            std::stringstream context { data.source_context };
            string line;
            while(std::getline(context, line) )
              {
              output << "   " << line << endl;
              }
            output << "\n\n";
            }
          ++it;
          }
        }
      }
    main_output << endl << index_rst_footer << endl;
    }
  catch( std::exception const & err )
    {
    std::cerr << err.what() << endl;
    }

}
/*
GMap_Dj_Core.cpp
=================================================================

file GMap_Dj_Base.h line 3663
-----------------------------------------------------------------
.. error:: implicit conversion from type 'int' of value -512 (32-bit, signed) to type 'WORD' (aka 'unsigned short') changed the value to 65024 (16-bit, unsigned)

``llvm-symbolizer -demangle -addresses -inlining -pretty-print -functions=short  -e aAM-libs/asan_dev/arm64-v8a/libautomapa.e063.so -print-source-context-lines=8 0x6ee873c 0x6e63b78 0x6d9f99c 0x6d7a5f4 0x6d699a8 0x6f4a8ac 0x6cd6f60 0x6cd04a8 0x5f2b8c4 0x5f2bb44``

.. code-block:: C++

    0x6ee873c: Initialize at /md1/home/artur/projects/ameu_online_aam/Components/GMapCore/Include/GMap_Dj_Base.h:3663:22
    3659  :       if(iBitsPerKey < 16) {*/
