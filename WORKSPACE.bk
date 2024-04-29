workspace(name = "silifuzz")

load("@bazel_tools//tools/build_defs/repo:git.bzl", "new_git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

###############################################################################
# Bazel Skylib (transitively required by com_google_absl).
###############################################################################

http_archive(
    name = "bazel_skylib",
    sha256 = "f24ab666394232f834f74d19e2ff142b0af17466ea0c69a3f4c276ee75f6efce",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-skylib/releases/download/1.4.0/bazel-skylib-1.4.0.tar.gz",
        "https://github.com/bazelbuild/bazel-skylib/releases/download/1.4.0/bazel-skylib-1.4.0.tar.gz",
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
    sha256 = "2037875b9a4456dce4a79d112a8ae885bbc4aad968e6587dca6e64f3a0900cdf",
    strip_prefix = "rules_cc-0.0.9",
    urls = ["https://github.com/bazelbuild/rules_cc/releases/download/0.0.9/rules_cc-0.0.9.tar.gz"],
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
    name = "com_google_absl",
    sha256 = "0ddd37f347c58d89f449dd189a645bfd97bcd85c5284404a3af27a3ca3476f39",
    strip_prefix = "abseil-cpp-fad946221cec37175e762c399760f54b9de9a9fa",
    url = "https://github.com/abseil/abseil-cpp/archive/fad946221cec37175e762c399760f54b9de9a9fa.tar.gz",
)

###############################################################################
# GoogleTest/GoogleMock
###############################################################################

http_archive(
    name = "com_google_googletest",
    sha256 = "2ebedb9330ff0e7e07abd77df9bd8c62692016a8138a4722f5259e7f657c89c1",
    strip_prefix = "googletest-b3a9ba2b8e975550799838332803d468797ae2e1",
    url = "https://github.com/google/googletest/archive/b3a9ba2b8e975550799838332803d468797ae2e1.tar.gz",
)

###############################################################################
# Protobufs
###############################################################################
# proto_library, cc_proto_library, and java_proto_library rules implicitly
# depend on @com_google_protobuf for protoc and proto runtimes.
# This statement defines the @com_google_protobuf repo.
http_archive(
    name = "com_google_protobuf",
    sha256 = "8ff511a64fc46ee792d3fe49a5a1bcad6f7dc50dfbba5a28b0e5b979c17f9871",
    strip_prefix = "protobuf-25.2",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/v25.2.tar.gz"],
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

http_archive(
    name = "rules_proto",
    sha256 = "dc3fb206a2cb3441b485eb1e423165b231235a1ea9b031b4433cf7bc1fa460dd",
    strip_prefix = "rules_proto-5.3.0-21.7",
    url = "https://github.com/bazelbuild/rules_proto/archive/refs/tags/5.3.0-21.7.tar.gz",
)

load("@rules_proto//proto:repositories.bzl", "rules_proto_dependencies", "rules_proto_toolchains")

rules_proto_dependencies()

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
FUZZTEST_COMMIT = "cd852157d0effbd727ef228912d6c72b5376aef4"

http_archive(
    name = "com_google_fuzztest",
    integrity = "sha256-a+nYhfSkrvuFIKhstxXvT64T1tGXiemm0pJe5YWIO84=",
    strip_prefix = "fuzztest-" + FUZZTEST_COMMIT,
    url = "https://github.com/google/fuzztest/archive/" + FUZZTEST_COMMIT + ".zip",
)

# Required by com_google_fuzztest.
http_archive(
    name = "com_googlesource_code_re2",
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
    sha256 = "f8386e44e16d044c1d7151c0b553bb7075d79583d4fa9e613a4be452599e0795",
    strip_prefix = "riegeli-411cda7f6aa81f8b8591b04cf141b1decdcc928c",
    url = "https://github.com/google/riegeli/archive/411cda7f6aa81f8b8591b04cf141b1decdcc928c.tar.gz",
)

################################################################################
# Dependencies required for Riegeli
################################################################################

http_archive(
    name = "highwayhash",
    build_file = "@com_google_riegeli//third_party:highwayhash.BUILD",
    sha256 = "cf891e024699c82aabce528a024adbe16e529f2b4e57f954455e0bf53efae585",
    strip_prefix = "highwayhash-276dd7b4b6d330e4734b756e97ccfb1b69cc2e12",
    urls = ["https://github.com/google/highwayhash/archive/276dd7b4b6d330e4734b756e97ccfb1b69cc2e12.zip"],  # 2019-02-22
)

http_archive(
    name = "org_brotli",
    sha256 = "84a9a68ada813a59db94d83ea10c54155f1d34399baf377842ff3ab9b3b3256e",
    strip_prefix = "brotli-3914999fcc1fda92e750ef9190aa6db9bf7bdb07",
    urls = ["https://github.com/google/brotli/archive/3914999fcc1fda92e750ef9190aa6db9bf7bdb07.zip"],  # 2022-11-17
)

http_archive(
    name = "net_zstd",
    build_file = "@com_google_riegeli//third_party:net_zstd.BUILD",
    sha256 = "b6c537b53356a3af3ca3e621457751fa9a6ba96daf3aebb3526ae0f610863532",
    strip_prefix = "zstd-1.4.5/lib",
    urls = ["https://github.com/facebook/zstd/archive/v1.4.5.zip"],  # 2020-05-22
)

http_archive(
    name = "snappy",
    build_file = "@com_google_riegeli//third_party:snappy.BUILD",
    sha256 = "38b4aabf88eb480131ed45bfb89c19ca3e2a62daeb081bdf001cfb17ec4cd303",
    strip_prefix = "snappy-1.1.8",
    urls = ["https://github.com/google/snappy/archive/1.1.8.zip"],  # 2020-01-14
)
