workspace(name = "silifuzz")

load("@bazel_tools//tools/build_defs/repo:git.bzl", "new_git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

###############################################################################
# Bazel Skylib (transitively required by abseil-cpp).
###############################################################################

http_archive(
    name = "bazel_skylib",
    sha256 = "bc283cdfcd526a52c3201279cda4bc298652efa898b10b4db0837dc51652756f",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.7.1/bazel-skylib-1.7.1.tar.gz",
        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.7.1/bazel-skylib-1.7.1.tar.gz",
    ],
)

load("@bazel_skylib//:workspace.bzl", "bazel_skylib_workspace")

bazel_skylib_workspace()

###############################################################################
# C++ build rules
# Configure the bootstrapped Clang and LLVM toolchain for Bazel.
###############################################################################

http_archive(
    name = "rules_cc",
    sha256 = "712d77868b3152dd618c4d64faaddefcc5965f90f5de6e6dd1d5ddcd0be82d42",
    strip_prefix = "rules_cc-0.1.1",
    urls = ["https://github.com/bazelbuild/rules_cc/releases/download/0.1.1/rules_cc-0.1.1.tar.gz"],
)

http_archive(
    name = "rules_python",
    sha256 = "9d04041ac92a0985e344235f5d946f71ac543f1b1565f2cdbc9a2aaee8adf55b",
    strip_prefix = "rules_python-0.26.0",
    url = "https://github.com/bazelbuild/rules_python/releases/download/0.26.0/rules_python-0.26.0.tar.gz",
)

load("@rules_python//python:repositories.bzl", "py_repositories")

py_repositories()

###############################################################################
# Abseil
###############################################################################

http_archive(
    name = "abseil-cpp",
    integrity = "sha256-33rryIpf8T3M5jdr3SkEmUO4hahMMCFrSkUbUPoLL14=",
    strip_prefix = "abseil-cpp-93c112c587269e778494e828b23e63ae70bd451e",
    url = "https://github.com/abseil/abseil-cpp/archive/93c112c587269e778494e828b23e63ae70bd451e.tar.gz",
    patches = ["@silifuzz//:third_party/absl_endian_visibility.patch"],
    patch_args = ["-p1"],
)

###############################################################################
# GoogleTest/GoogleMock
###############################################################################

http_archive(
    name = "com_google_googletest",
    sha256 = "2ebedb9330ff0e7e07abd77df9bd8c62692016a8138a4722f5259e7f657c89c1",
    strip_prefix = "googletest-b3a9ba2b8e975550799838332803d468797ae2e1",
    url = "https://github.com/google/googletest/archive/b3a9ba2b8e975550799838332803d468797ae2e1.tar.gz",
    repo_mapping = {"@com_google_absl": "@abseil-cpp",
                    "@com_googlesource_code_re2": "@re2"},
)

###############################################################################
# Protobufs
###############################################################################
# proto_library, cc_proto_library, and java_proto_library rules implicitly
# depend on @com_google_protobuf for protoc and proto runtimes.
# This statement defines the @com_google_protobuf repo.
http_archive(
    name = "com_google_protobuf",
    integrity = "sha256-B6Q9iP5aOOQ0x/lBKcrVakxDpR+ZM2B00HmcL31ORMU=",
    strip_prefix = "protobuf-30.2",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/v30.2.tar.gz"],
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

load("@rules_java//java:rules_java_deps.bzl", "rules_java_dependencies")

rules_java_dependencies()

load("@rules_java//java:repositories.bzl", "rules_java_toolchains")

rules_java_toolchains()

load("@rules_python//python:repositories.bzl", "py_repositories")

py_repositories()

http_archive(
    name = "rules_proto",
    sha256 = "14a225870ab4e91869652cfd69ef2028277fc1dc4910d65d353b62d6e0ae21f4",
    strip_prefix = "rules_proto-7.1.0",
    url = "https://github.com/bazelbuild/rules_proto/archive/refs/tags/7.1.0.tar.gz",
)

load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies")

rules_proto_dependencies()

load("@rules_proto//proto:toolchains.bzl", "rules_proto_toolchains")

rules_proto_toolchains()

###############################################################################
# Minor third_party dependencies
###############################################################################

lss_ver = "93e5acf3ef8793cad821c6af42612685e17392d8"

new_git_repository(
    name = "lss",
    build_file = "@silifuzz//:third_party/BUILD.lss",
    commit = lss_ver,
    remote = "https://chromium.googlesource.com/linux-syscall-support",
    shallow_since = "1705605906 +0000",
)

new_git_repository(
    name = "cityhash",
    build_file = "@silifuzz//:third_party/BUILD.cityhash",
    commit = "8af9b8c2b889d80c22d6bc26ba0df1afb79a30db",
    patch_cmds = [
        # Running "configure" creates the config.h file needed for this library.
        "./configure",
        "mv config.h src",
        """sed -i -e 's/<city.h>/"city.h"/' src/*.cc src/*.h""",
        """sed -i -e 's/<citycrc.h>/"citycrc.h"/' src/*.cc""",
    ],
    remote = "https://github.com/google/cityhash",
    shallow_since = "1375313681 +0000",
)

new_git_repository(
    name = "mbuild",
    build_file = "@silifuzz//:third_party/BUILD.mbuild",
    commit = "75cb46e6536758f1a3cdb3d6bd83a4a9fd0338bb",
    patch_cmds = [
        "rm -f setup.py",
        "mv mbuild/*.py .",
    ],
    remote = "https://github.com/intelxed/mbuild",
    shallow_since = "1659030943 +0300",
)

new_git_repository(
    name = "libxed",
    build_file = "@silifuzz//:third_party/BUILD.libxed",
    commit = "d7d46c73fb04a1742e99c9382a4acb4ed07ae272",
    patch_cmds = [
        "sed -i -e 's|xed/xed-interface.h|xed-interface.h|' examples/xed-tester.c",
    ],
    remote = "https://github.com/intelxed/xed",
    shallow_since = "1697457597 +0300",
)

http_archive(
    name = "liblzma",
    build_file = "@silifuzz//:third_party/BUILD.liblzma",
    sha256 = "f6f4910fd033078738bd82bfba4f49219d03b17eb0794eb91efbae419f4aba10",
    strip_prefix = "xz-5.2.5",
    urls = [
        "https://storage.googleapis.com/tensorstore-bazel-mirror/tukaani.org/xz/xz-5.2.5.tar.gz",
        "https://tukaani.org/xz/xz-5.2.5.tar.gz",
    ],
)

# Google benchmark. Official release 1.7.0
http_archive(
    name = "com_github_google_benchmark",
    sha256 = "3aff99169fa8bdee356eaa1f691e835a6e57b1efeadb8a0f9f228531158246ac",
    strip_prefix = "benchmark-1.7.0",
    urls = ["https://github.com/google/benchmark/archive/refs/tags/v1.7.0.tar.gz"],
)

# Capstone disassembler
new_git_repository(
    name = "capstone",
    build_file = "@silifuzz//:third_party/BUILD.capstone",
    commit = "702dbe78ca116de8ec65f122d9202c2c1f4a2b4c",
    remote = "https://github.com/capstone-engine/capstone.git",
)

# Unicorn for the proxies
new_git_repository(
    name = "unicorn",
    build_file = "@silifuzz//:third_party/BUILD.unicorn",
    commit = "d4b92485b1a228fb003e1218e42f6c778c655809",
    patch_cmds = [
        # crc32 and crc32c functions are prefixed with "unicorn_" to avoid linking errors from
        # symbol conflicts with other libraries (e.g. zlib). We need to match the opening bracket so
        # that we change only the function names, and not the header/argument/helper macros.
        # We can't easily glob the files like with ** operators in bash, so we use `find` to glob
        # the files and then `sed` to replace the function names in those files.
        """find qemu '(' -name "*.h" -o -name "*.c" ')' -type f \
                -exec sed -i -e 's/\\b\\(crc32[c]\\{0,1\\}\\)(/unicorn_\\1(/' {} +""",
    ],
    remote = "https://github.com/unicorn-engine/unicorn",
    shallow_since = "1687038706 +0200",
)

http_archive(
    name = "absl_py",
    sha256 = "b9130d6f49a21dc44f56da89d5e8409807e93d28c194c23e27777f3c8cceef81",
    strip_prefix = "abseil-py-1.2.0",
    urls = ["https://github.com/abseil/abseil-py/archive/refs/tags/v1.2.0.tar.gz"],
)

# To use the latest version of FuzzTest, update this regularly to the latest
# commit in the main branch: https://github.com/google/fuzztest/commits/main
FUZZTEST_COMMIT = "429d46c8154af75befa37a729ead2e9b6485347f"

http_archive(
    name = "com_google_fuzztest",
    sha256 = "0212cc439fb157130668068e441d9e7bcfb10ab3f80c270b94e3b8f0c141ff55",
    strip_prefix = "fuzztest-" + FUZZTEST_COMMIT,
    url = "https://github.com/google/fuzztest/archive/" + FUZZTEST_COMMIT + ".zip",
)

# Required by com_google_fuzztest.
http_archive(
    name = "re2",
    sha256 = "f89c61410a072e5cbcf8c27e3a778da7d6fd2f2b5b1445cd4f4508bee946ab0f",
    strip_prefix = "re2-2022-06-01",
    url = "https://github.com/google/re2/archive/refs/tags/2022-06-01.tar.gz",
)

# libpf4m required by PMU event proxy
new_git_repository(
    name = "libpfm4",
    build_file = "@silifuzz//:third_party/BUILD.libpfm4",
    commit = "535c204286d84079a8102bdc7a53b1f50990c0a3",
    remote = "https://git.code.sf.net/p/perfmon2/libpfm4",
)

http_archive(
    name = "com_google_riegeli",
    integrity = "sha256-/ALALKdLpx6VyrimK62Q0fgO9eoBHHppsRZc6l329Oc=",
    strip_prefix = "riegeli-3385e3cbc5c1a1380eb99b7cf0b021c1ae0b2c30",
    url = "https://github.com/google/riegeli/archive/3385e3cbc5c1a1380eb99b7cf0b021c1ae0b2c30.tar.gz",
    repo_mapping = {"@com_google_absl": "@abseil-cpp"},
)

################################################################################
# Dependencies required for Riegeli
################################################################################

http_archive(
    name = "highwayhash",
    build_file = "@silifuzz//:third_party/BUILD.highwayhash",
    integrity = "sha256-dEp0gr0f5NnP5mMuwlS5J+y5v2URYZU9OByx5Pbz+6M=",
    strip_prefix = "highwayhash-5ad3bf8444cfc663b11bf367baaa31f36e7ff7c8",
    url = "https://github.com/google/highwayhash/archive/5ad3bf8444cfc663b11bf367baaa31f36e7ff7c8.tar.gz",
)

http_archive(
    name = "org_brotli",
    integrity = "sha256-5yCmyilCi4A/StFlNxdx9TmPq6OX7fZ3iDehhZnqE/8=",
    strip_prefix = "brotli-1.1.0",
    url = "https://github.com/google/brotli/archive/refs/tags/v1.1.0.tar.gz",
)

http_archive(
    name = "net_zstd",
    build_file = "@silifuzz//:third_party/BUILD.net_zstd",
    integrity = "sha256-jCngbPQqrMHq/EB3ri7Gxvy5amJhV+BZPV6Co0/UA8E=",
    strip_prefix = "zstd-1.5.6",
    url = "https://github.com/facebook/zstd/releases/download/v1.5.6/zstd-1.5.6.tar.gz",
)

http_archive(
    name = "snappy",
    integrity = "sha256-m48Q+7XjvBEvLl5k+BPLc/rqQuycUzpQI7WuCK7e9C4=",
    strip_prefix = "snappy-1.2.0",
    url = "https://github.com/google/snappy/archive/refs/tags/1.2.0.tar.gz",
)
