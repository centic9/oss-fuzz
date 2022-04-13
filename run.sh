#!/bin/bash
# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

set -eu

function usage() {
  echo Usage
  echo "run.sh [-introspect] [-baserunner] [-reimage] [-rebuild] [-nofuzzing] [-nocoverage] <project>"
  echo "    -introspect:   run introspector for specified project"
  echo "    -baserunner:   build image for base_runner locally"
  echo "    -reimage:      rebuild image for fuzzing of the project"
  echo "    -rebuild:      build fuzzers for project and run checks"
  echo "    -nofuzzing:    do not run actual fuzzing"
  echo "    -nocoverage:   do not run coverage collecting step"
  echo "    -reproduce:    run a given test-case"
  echo
  echo "Sample execution: "
  echo "    ./run.sh -reimage -rebuild apache-poi"
}

PROJECT=apache-poi
INTROSPECT=0
BASE_RUNNER=0
REIMAGE=0
REBUILD=0
FUZZING=1
COVERAGE=1
REPRODUCE=0

if [ $# -eq 0 ]; then
  usage

  exit 1
fi

while [ $# -gt 0 ]
do
  key="$1"
  shift
  case $key in
    -introspect)
      INTROSPECT=1
      ;;
    -baserunner)
      BASE_RUNNER=1
      ;;
    -reimage)
      REIMAGE=1
      ;;
    -rebuild)
      REBUILD=1
      ;;
    -nofuzzing)
      FUZZING=0
      ;;
    -nocoverage)
      COVERAGE=0
      ;;
    -reproduce)
      REPRODUCE=1
      ;;
    -h|--help)
      usage

      exit 1
      ;;
    *)
      PROJECT=${key}
      ;;
  esac
done

if [ ! -d "projects/${PROJECT}" ]; then
  echo "Could not find project directory at projects/${PROJECT}"

  exit 2
fi

echo
echo Running for project ${PROJECT} with options INTROSPECT=${INTROSPECT}, BASE_RUNNER=${BASE_RUNNER}, REIMAGE=${REIMAGE}, REBUILD=${REBUILD}, FUZZING=${FUZZING}, COVERAGE=${COVERAGE}

if [ "${OSTYPE}" != "CYGWIN" -a "${OSTYPE}" != "msys" ]; then
  COUNT=`find build/out/${PROJECT}/ -user root | wc -l`
  if [ ${COUNT} -ne 0 ]; then
    echo
    echo Adjusting ${COUNT} files owned by root
    find build/out/${PROJECT}/ -user root -print0 | xargs -0 sudo chown dstadler:
  fi
fi

if [ ${INTROSPECT} -eq 1 ]; then
  echo
  echo "Running introspector"
  nice -n 19 python3 infra/helper.py introspector ${PROJECT}

  exit $?
fi

if [ ${BASE_RUNNER} -eq 1 ]; then
  echo
  echo "Building image for base_runner locally"
  # docker build -t gcr.io/oss-fuzz-base/base-runner infra/base-images/base-runner
  nice -n 19 python3 infra/helper.py build_image base-runner --no-pull --cache
fi

if [ ${REIMAGE} -eq 1 ]; then
  echo
  echo "Building image"
  nice -n 19 python3 infra/helper.py build_image ${PROJECT}
fi

if [ ${REBUILD} -eq 1 ]; then
  echo
  echo "Building fuzzers"
  nice -n 19 python3 infra/helper.py build_fuzzers ${PROJECT}

  echo
  echo "Checking resulting image"
  nice -n 19 python3 infra/helper.py check_build ${PROJECT}
fi

if [ ${REPRODUCE} -eq 1 ]; then
  echo
  echo "Reproducing ${PROJECT}"

  nice -n 19 python3 infra/helper.py reproduce ${PROJECT} POIFuzzer /tmp/clusterfuzz-testcase-minimized-POIFuzzer-4602470414024704

  exit $?
fi

echo
echo Running presubmit
nice -n 19 python3 infra/presubmit.py

if [ ${FUZZING} -eq 1 ]; then
  for i in `find projects/${PROJECT} -name *Fuzzer.java`; do
    echo
    echo Running Fuzzer `basename $i .java`
    mkdir -p build/corpus/${PROJECT}/`basename $i .java`/
    nice -n 19 python3 infra/helper.py run_fuzzer \
      --corpus-dir build/corpus/${PROJECT}/`basename $i .java`/ \
      ${PROJECT} \
      `basename $i .java` \
      -- -max_total_time=1000 \
      -timeout=120 \
      || break
  done
fi

if [ ${COVERAGE} -eq 1 ]; then
  COVERAGE_EXTRA_ARGS=`grep coverage_extra_args projects/apache-poi/project.yaml | sed -e 's/coverage_extra_args: //g'`

  echo
  echo Computing coverage of local corpus with COVERAGE_EXTRA_ARGS: ${COVERAGE_EXTRA_ARGS}
  # store corpus in build/corpus/apache-poi/XLSX2CSVFuzzer/
  if [ -d projects/${PROJECT}/src ]; then
    cp -a projects/${PROJECT}/src build/out/${PROJECT}/
  else
    mkdir -p build/out/${PROJECT}/src
    cp -a projects/${PROJECT}/*.java build/out/${PROJECT}/src/
  fi
  nice -n 19 python3 infra/helper.py coverage --no-corpus-download ${PROJECT} ${COVERAGE_EXTRA_ARGS}
fi
