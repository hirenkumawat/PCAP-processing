JOBS      ?= 8
MAKEFLAGS += --no-print-directory

default: all

all:
	( mkdir -p build && cd build && cmake $(CMAKE_OPTIONS) .. && cmake --build . --config Release -j${JOBS} )

dash1:
	( mkdir -p build_dash1 && cd build_dash1 && cmake $(CMAKE_OPTIONS) .. && cmake --build . --config Release -j${JOBS} )

bf3:
	( mkdir -p build_bf3 && cd build_bf3 && cmake $(CMAKE_OPTIONS) .. && cmake --build . --config Release -j${JOBS} )

kingpin2:
	( mkdir -p build_kingpin2 && cd build_kingpin2 && cmake $(CMAKE_OPTIONS) .. && cmake --build . --config Release -j${JOBS} )

debug:
	( mkdir -p build && cd build && cmake $(CMAKE_OPTIONS) .. && cmake --build . --config Debug -j${JOBS} )

install: all
	( cd build && cmake --install . --config Release )

rpm: all
	( cd build && cpack -G RPM . )

clean:
	( rm -rf build )

