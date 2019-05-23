# logcat_symbolizer
Tool for collecting asan and ubsan sainitizer routput from android logcat and transforming results to html with source code annotation with llvm-symbolizer
It can create output as 
- source annotated plain text file
- source annotated RetText files for generating html with sphinx where bugs are sorted by file and easy to read index is created to subpages

# sanitize on android
With android version 8.1+ it's quie easy using wraph.sh 

my wrap.sh for arm64-v8a
```
#!/system/bin/sh
HERE="$(cd "$(dirname "$0")" && pwd)"
export ASAN_OPTIONS=log_to_syslog=false,allow_user_segv_handler=1,detect_stack_use_after_return=1,check_initialization_order=true,quarantine_size_mb=64,color=never,new_delete_type_mismatch=0
export UBSAN_OPTIONS=print_stacktrace=1,log_to_syslog=false,color=never
export LD_PRELOAD="$HERE/libclang_rt.asan-aarch64-android.so $HERE/libc++_shared.so"
exec "$@"
```

put this file into
```app/src/main/java/resources/lib/arm64-v8a/```

CMake CXX_FLAGS (assuming ndk-r20 with llvm/clang-8 )
```
set(SANITIZE_ASAN_FLAGS "-fsanitize=address -fsanitize-address-use-after-scope -fno-optimize-sibling-calls"  )
set(SANITIZE_UBSAN_FLAGS "-fsanitize=alignment,bool,builtin,bounds,enum,float-cast-overflow,float-divide-by-zero,implicit-unsigned-integer-truncation,implicit-signed-integer-truncation,implicit-integer-sign-change,integer-divide-by-zero,nonnull-attribute,null,nullability-arg,nullability-assign,nullability-return,object-size,pointer-overflow,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,unsigned-integer-overflow,vla-bound"  )
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${SANITIZE_ASAN_FLAGS} ${SANITIZE_UBSAN_FLAGS}"  )
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${SANITIZE_ASAN_FLAGS} ${SANITIZE_UBSAN_FLAGS}"  )
```
I use too -fuse-ld=lld

# collecting data form log cat

just
adb -s DEVICE_ID logcat --clear
adb -s DEVICE_ID logcat >log.txt

run application

# processing output
 - ReText ```./logcat_symbolizer -l log.txt -r some_directory_for_retext```
 - plan text ```./logcat_symbolizer -l log.txt -o plain_text.txt```
 - stdout ```./logcat_symbolizer -l log.txt```
