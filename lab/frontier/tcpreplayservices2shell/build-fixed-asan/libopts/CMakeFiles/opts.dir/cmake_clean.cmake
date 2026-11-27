file(REMOVE_RECURSE
  "libopts.a"
  "libopts.pdb"
)

# Per-language clean rules from dependency scanning.
foreach(lang C)
  include(CMakeFiles/opts.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
